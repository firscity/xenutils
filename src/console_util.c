#include <xen/generic.h>
#include <xen/public/io/console.h>
#include <xen/public/memory.h>
#include <xen/public/xen.h>

#include <domain.h>

#include <init.h>
#include <kernel.h>
#include <string.h>

static bool console_thrd_stop = false;
K_KERNEL_STACK_DEFINE(read_thrd_stack, 8192);
static struct k_thread read_thrd;
static k_tid_t read_tid;

/*
 * Need to read from OUT ring in dom0, domU writes logs there
 * TODO: place this in separate driver
 */
static int read_from_ring(struct xencons_interface *intf, char *str, int len)
{
	int recv = 0;
	XENCONS_RING_IDX cons = intf->out_cons;
	XENCONS_RING_IDX prod = intf->out_prod;
	XENCONS_RING_IDX out_idx = 0;

	compiler_barrier();
	__ASSERT((prod - cons) <= sizeof(intf->out),
			"Invalid input ring buffer");

	while (cons != prod && recv < len) {
		out_idx = MASK_XENCONS_IDX(cons, intf->out);
		str[recv] = intf->out[out_idx];
		recv++;
		cons++;
	}

	compiler_barrier();
	intf->out_cons = cons;

	return recv;
}

static struct k_sem sem;
static evtchn_port_t local_console_chn;

void console_read_thrd(void *intf, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	char buffer[128];
	int recv;

	compiler_barrier();
	while (!console_thrd_stop) {
		k_sem_take(&sem, K_FOREVER);

		do {
			memset(buffer, 0, sizeof(buffer));
			recv = read_from_ring((struct xencons_interface *) intf, buffer, sizeof(buffer));
			if (recv) {
				printk("%s", buffer);
			}
		} while (recv);
	}
}

void evtchn_callback(void *priv)
{
	k_sem_give(&sem);
}

int start_domain_console(struct xen_domain *domain)
{
	local_console_chn = evtchn_bind_interdomain(domain->domid, domain->console_evtchn);

	k_sem_init(&sem, 0, 1);

	bind_event_channel(local_console_chn, evtchn_callback, NULL);

	console_thrd_stop = false;
	read_tid = k_thread_create(&read_thrd, read_thrd_stack,
				K_KERNEL_STACK_SIZEOF(read_thrd_stack),
				console_read_thrd, domain->intf, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;
}

int stop_domain_console(void)
{
	int rc;

	if (!read_tid) {
		printk("No console thread is running!\n");
		return -ESRCH;
	}

	unbind_event_channel(local_console_chn);
	rc = evtchn_close(local_console_chn);

	console_thrd_stop = true;
	/* Send event to end read cycle */
	k_sem_give(&sem);

	read_tid = NULL;
	return 0;
}
