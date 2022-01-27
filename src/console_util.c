#include <xen/generic.h>
#include <xen/public/io/console.h>
#include <xen/public/xen.h>


#include <xen/public/memory.h>

#include "domain.h"

#include <init.h>
#include <kernel.h>
#include <string.h>

bool console_thrd_stop = false;

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

void console_read_thrd(void *intf, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	char buffer[128];
	int recv;


	printk("Starting read thread, intf = %p!\n", intf);

	compiler_barrier();
	while (!console_thrd_stop) {
		memset(buffer, 0, sizeof(buffer));
		recv = read_from_ring((struct xencons_interface *) intf, buffer, sizeof(buffer));
		if (recv) {
			printk("[domain hvc] %s", buffer);
		}
		k_sleep(K_MSEC(1000));
	}

	printk("Exiting read thread!\n");
}

K_KERNEL_STACK_DEFINE(read_thrd_stack, 8192);
struct k_thread read_thrd;
k_tid_t read_tid;

int start_domain_console(struct xen_domain *domain)
{
	printk("creating read thread\n");
	console_thrd_stop = false;
	read_tid = k_thread_create(&read_thrd, read_thrd_stack,
				K_KERNEL_STACK_SIZEOF(read_thrd_stack),
				console_read_thrd, domain->intf, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;
}

int stop_domain_console(struct xen_domain *domain)
{
	console_thrd_stop = true;
	return 0;
}
