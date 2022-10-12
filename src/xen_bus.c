#include <stdint.h>
#include <string.h>

#include <xen/events.h>
#include <xen/public/hvm/params.h>
#include <xen/public/io/xs_wire.h>
#include <xen/hvm.h>

#include "domain.h"
#include "processing.h"

#define STACK_SIZE_PER_DOM (32 * 1024)
K_KERNEL_STACK_DEFINE(xenbus_thrd_stack, STACK_SIZE_PER_DOM *DOM_MAX);
static int stack_slots[DOM_MAX] = { 0 };

#define MAX_NAME_LEN 64

K_MUTEX_DEFINE(xsel_mutex);
K_MUTEX_DEFINE(pfl_mutex);

static bool check_indexes(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod)
{
	return ((prod - cons) > XENSTORE_RING_SIZE);
}

static uint32_t get_input_offset(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod, uint32_t *len)
{
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);
	int delta = prod - cons;
	if (delta < *len) {
		*len = delta;
	}

	return MASK_XENSTORE_IDX(cons);
}

static uint32_t get_output_offset(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod, uint32_t *len)
{
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
	int delta = XENSTORE_RING_SIZE - cons + prod;
	if (delta < *len) {
		*len = delta;
	}

	return MASK_XENSTORE_IDX(prod);
}

void write_xb(struct xenstore_domain_interface *intf, uint8_t *data, uint32_t len)
{
	uint32_t blen = 0;
	uint32_t offset = 0;

	do {
		uint32_t tail = get_output_offset(intf->rsp_cons, intf->rsp_prod, &blen);

		if (blen == 0) {
			continue;
		}

		uint32_t effect = blen > len ? len : blen;
		memcpy(intf->rsp + tail, data + offset, effect);
		offset += effect;
		len -= effect;
		intf->rsp_prod += effect;
	} while (len > 0);
}

uint32_t read_xb(struct xen_domain *domain, uint8_t *data, uint32_t len)
{
	uint32_t blen = 0;
	uint32_t offset = 0;
	struct xenstore_domain_interface *intf = domain->domint;

	do {
		uint32_t prod = intf->req_prod;
		uint32_t ring_offset = get_input_offset(intf->req_cons, prod, &blen);

		if (blen == 0) {
			notify_evtchn(domain->local_xenbus_evtchn);
			return 0;
		}

		uint32_t effect = (blen > len) ? len : blen;
		memcpy(data + offset, intf->req + ring_offset, effect);
		offset += effect;
		len -= effect;
		intf->req_cons += effect;
	} while (len > 0);

	return offset;
}

void send_reply_sz(struct xen_domain *domain, uint32_t id, uint32_t msg_type, const char *payload,
		   int sz)
{
	struct xenstore_domain_interface *intf = domain->domint;

	if (check_indexes(intf->rsp_cons, intf->rsp_prod)) {
		intf->rsp_cons = 0;
		intf->rsp_prod = 0;
	}

	struct xsd_sockmsg h = { .req_id = id, .type = msg_type, .len = sz };

	write_xb(intf, (uint8_t *)&h, sizeof(struct xsd_sockmsg));
	notify_evtchn(domain->local_xenbus_evtchn);
	write_xb(intf, (uint8_t *)payload, sz);
	notify_evtchn(domain->local_xenbus_evtchn);
}

void send_reply(struct xen_domain *domain, uint32_t id, uint32_t msg_type, const char *payload)
{
	send_reply_sz(domain, id, msg_type, payload, strlen(payload) + 1);
}

void send_reply_read(struct xen_domain *domain, uint32_t id, uint32_t msg_type, char *payload)
{
	send_reply_sz(domain, id, msg_type, payload, strlen(payload));
}

void xb_chn_cb(void *priv)
{
	struct xen_domain *domain = (struct xen_domain *)priv;
	k_sem_give(&domain->xb_sem);
}

int start_domain_stored(struct xen_domain *domain)
{
	size_t slot = 0;

	k_sem_init(&domain->xb_sem, 0, 1);
	domain->local_xenbus_evtchn = evtchn_bind_interdomain(domain->domid, domain->xenbus_evtchn);

	bind_event_channel(domain->local_xenbus_evtchn, xb_chn_cb, (void *)domain);

	int rc = hvm_set_parameter(HVM_PARAM_STORE_EVTCHN, domain->domid, domain->xenbus_evtchn);
	if (rc) {
		printk("Failed to set domain xenbus evtchn param, rc= %d\n", rc);
		return rc;
	}

	domain->xenbus_thrd_stop = false;

	for (; slot < DOM_MAX && stack_slots[slot] != 0; ++slot)
		;

	if (slot >= DOM_MAX) {
		printk("Unable to find memory for xenbus stack (%ld >= MAX:%d)\n", slot, DOM_MAX);
		return 1;
	}

	stack_slots[slot] = domain->domid;
	domain->stack_slot = slot;
	domain->xenbus_tid =
		k_thread_create(&domain->xenbus_thrd, xenbus_thrd_stack + STACK_SIZE_PER_DOM * slot,
				K_KERNEL_STACK_SIZEOF(xenbus_thrd_stack) / DOM_MAX, xenbus_evt_thrd,
				domain, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;
}

int stop_domain_stored(struct xen_domain *domain)
{
	int rc = 0;

	printk("Destroy domain=%p\n", domain);
	domain->xenbus_thrd_stop = true;
	k_sem_give(&domain->xb_sem);
	k_thread_join(&domain->xenbus_thrd, K_FOREVER);
	stack_slots[domain->stack_slot] = 0;
	unbind_event_channel(domain->local_xenbus_evtchn);
	rc = evtchn_close(domain->local_xenbus_evtchn);

	if (rc)
	{
		printk("Unable to close event channel %d, rc=%d\n", domain->local_xenbus_evtchn, rc);
	}

	return rc;
}

void xenbus_evt_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	uint32_t sz;
	uint32_t delta;
	struct xsd_sockmsg *header;
	char input_buffer[XENSTORE_RING_SIZE];
	struct xen_domain *domain = p1;
	struct xenstore_domain_interface *intf = domain->domint;

	domain->transaction = 0;
	domain->stop_transaction_id = 0;

	while (!domain->xenbus_thrd_stop) {
		if (intf->req_prod <= intf->req_cons)
		{
			k_sem_take(&domain->xb_sem, K_FOREVER);
		}

		header = (struct xsd_sockmsg*)input_buffer;
		sz = 0;

		do {
			delta = read_xb(domain, (uint8_t *)input_buffer + sz, sizeof(struct xsd_sockmsg));

			if (delta == 0)
			{
				/* Missing header data, nothing to read. Perhaps pending watch event from
				 * different domain. */
				break;
			}

			sz += delta;
		} while (sz < sizeof(struct xsd_sockmsg));

		if (sz == 0)
		{
			/* Skip message body processing */
			continue;
		}

		sz = 0;

		do
		{
			delta = read_xb(domain, (uint8_t *)input_buffer + sizeof(struct xsd_sockmsg) + sz, header->len);
			sz += delta;
		} while (sz < header->len);

		printk("Unsupported message type: %d\n", header->type);
		send_errno(domain, header->req_id, ENOSYS);

		notify_evtchn(domain->local_xenbus_evtchn);
	}
}
