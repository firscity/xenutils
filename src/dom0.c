/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <arch/arm64/hypercall.h>
#include <xen/dom0/domctl.h>
#include <xen/dom0/zimage.h>
#include <xen/generic.h>
#include <xen/hvm.h>
#include <xen/memory.h>
#include <xen/public/hvm/hvm_op.h>
#include <xen/public/hvm/params.h>
#include <xen/public/domctl.h>
#include <xen/public/xen.h>

#include <xen/public/io/console.h>

#include <init.h>
#include <kernel.h>
#include <string.h>

/* TODO: this should be read from some "config" */
#define DOMU_FLAGS		(XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap)
#define DOMU_MAX_VCPUS		1
#define DOMU_MAX_EVTCHN		10
#define DOMU_MAX_GNT_FRAMES	1
#define DOMU_MAX_MAPTRCK_FR	1

#define ARCH_DOMU_NR_SPIS	0

#define DOMU_MAXMEM_KB		65536

static void arch_prepare_domain_cfg(struct xen_arch_domainconfig *arch_cfg)
{
	arch_cfg->gic_version = XEN_DOMCTL_CONFIG_GIC_V2;
	arch_cfg->tee_type = XEN_DOMCTL_CONFIG_TEE_NONE;
	arch_cfg->nr_spis = ARCH_DOMU_NR_SPIS;
}

static void prepare_domain_cfg(struct xen_domctl_createdomain *cfg)
{
	cfg->flags = DOMU_FLAGS;
	cfg->max_vcpus = DOMU_MAX_VCPUS;
	cfg->max_evtchn_port = DOMU_MAX_EVTCHN;
	cfg->max_grant_frames = DOMU_MAX_GNT_FRAMES;
	cfg->max_maptrack_frames = DOMU_MAX_MAPTRCK_FR;

	arch_prepare_domain_cfg(&cfg->arch);
}

#define NR_MAGIC_PAGES		4
#define CONSOLE_PFN_OFFSET 0
#define XENSTORE_PFN_OFFSET 1
#define MEMACCESS_PFN_OFFSET 2
#define VUART_PFN_OFFSET 3

static int allocate_magic_pages(int domid, uint64_t base_pfn)
{
	int rc, i;
	uint64_t nr_exts = NR_MAGIC_PAGES;
	xen_pfn_t magic_base_pfn = PHYS_PFN(GUEST_MAGIC_BASE);
	xen_pfn_t extents[nr_exts];
	void *mapped_magic;
	xen_pfn_t mapped_base_pfn, mapped_pfns[nr_exts];
	int err_codes[nr_exts];
	struct xen_domctl_cacheflush cacheflush;


	for (i = 0; i < nr_exts; i++) {
		extents[i] = magic_base_pfn + i;
	}
	rc = xendom_populate_physmap(domid, 0, nr_exts, 0, extents);

	/* Need to clear memory content of magic pages */
	mapped_magic = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE * nr_exts);
	mapped_base_pfn = PHYS_PFN((uint64_t) mapped_magic);
	for (i = 0; i < nr_exts; i++) {
		mapped_pfns[i] = mapped_base_pfn + i;
	}
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domid, XENMAPSPACE_gmfn_foreign,
				nr_exts, extents, mapped_pfns, err_codes);

	memset(mapped_magic, 0, XEN_PAGE_SIZE * nr_exts);

	cacheflush.start_pfn = mapped_base_pfn;
	cacheflush.nr_pfns = nr_exts;
	rc = xen_domctl_cacheflush(0, &cacheflush);
	printk("Return code for xen_domctl_cacheflush = %d\n", rc);

	/* Needed to remove mapped DomU pages from Dom0 physmap */
	for (i = 0; i < nr_exts; i++) {
		rc = xendom_remove_from_physmap(DOMID_SELF, mapped_pfns[i]);
	}

	/*
	 * After this Dom0 will have memory hole in mapped_magic address,
	 * needed to populate memory on this address before freeing.
	 */
	rc = xendom_populate_physmap(DOMID_SELF, 0, nr_exts, 0, mapped_pfns);
	printk(">>> Return code = %d XENMEM_populate_physmap\n", rc);

	k_free(mapped_magic);

	/* TODO: Set HVM params for all allocated pages */
	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_PFN, domid, magic_base_pfn + CONSOLE_PFN_OFFSET);

	/* TODO: fix event-channels for pages */
	return rc;
}

/* Xen can populate physmap with different extent size, we are using 2M */
#define EXTENT_2M_SIZE_KB	2048
#define EXTENT_2M_PFN_SHIFT	9
static int prepare_domu_physmap(int domid, uint64_t base_pfn,
		uint64_t domain_mem_kb)
{
	int i, rc;
	uint64_t nr_exts = ceiling_fraction(domain_mem_kb, EXTENT_2M_SIZE_KB);
	xen_pfn_t extents[nr_exts];

	for (i = 0; i < nr_exts; i++) {
		extents[i] = base_pfn + (i << EXTENT_2M_PFN_SHIFT);
	}
	rc = xendom_populate_physmap(domid, EXTENT_2M_PFN_SHIFT, nr_exts, 0, extents);

	return allocate_magic_pages(domid, base_pfn);
}

extern char __zephyr_domu_start[];
extern char __zephyr_domu_end[];
uint64_t load_domu_image(int domid, uint64_t base_addr)
{
	int i, rc;
	void *mapped_domu;
	uint64_t mapped_base_pfn;
	uint64_t domu_size = __zephyr_domu_end - __zephyr_domu_start;
	uint64_t nr_pages = ceiling_fraction(domu_size, XEN_PAGE_SIZE);
	xen_pfn_t mapped_pfns[nr_pages];
	xen_pfn_t indexes[nr_pages];
	int err_codes[nr_pages];
	struct xen_domctl_cacheflush cacheflush;

	struct zimage64_hdr *zhdr = (struct zimage64_hdr *) __zephyr_domu_start;
	uint64_t base_pfn = PHYS_PFN(base_addr);

	mapped_domu = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE * nr_pages);
	mapped_base_pfn = PHYS_PFN((uint64_t) mapped_domu);

	for (i = 0; i < nr_pages; i++) {
		mapped_pfns[i] = mapped_base_pfn + i;
		indexes[i] = base_pfn + i;
	}

	rc = xendom_add_to_physmap_batch(DOMID_SELF, domid, XENMAPSPACE_gmfn_foreign,
				nr_pages, indexes, mapped_pfns, err_codes);
	printk("Return code for XENMEM_add_to_physmap_batch = %d\n", rc);
	printk("mapped_domu = %p\n", mapped_domu);
	printk("Zephyr DomU start addr = %p, end addr = %p, binary size = 0x%llx\n",
		__zephyr_domu_start, __zephyr_domu_end, domu_size);

	/* Copy binary to domain pages and clear cache */
	memcpy(mapped_domu, __zephyr_domu_start, domu_size);

	cacheflush.start_pfn = mapped_base_pfn;
	cacheflush.nr_pfns = nr_pages;
	rc = xen_domctl_cacheflush(0, &cacheflush);
	printk("Return code for xen_domctl_cacheflush = %d\n", rc);

	/* Needed to remove mapped DomU pages from Dom0 physmap */
	for (i = 0; i < nr_pages; i++) {
		rc = xendom_remove_from_physmap(DOMID_SELF, mapped_pfns[i]);
	}

	/*
	 * After this Dom0 will have memory hole in mapped_domu address,
	 * needed to populate memory on this address before freeing.
	 */
	rc = xendom_populate_physmap(DOMID_SELF, 0, nr_pages, 0, mapped_pfns);
	printk(">>> Return code = %d XENMEM_populate_physmap\n", rc);

	k_free(mapped_domu);

	/* .text start address in domU memory */
	return base_addr + zhdr->text_offset;
}

static struct xencons_interface *intf;
K_KERNEL_STACK_DEFINE(read_thrd_stack, 8192);
struct k_thread read_thrd;
k_tid_t read_tid;
bool console_thrd_stop = false;

/* Need to read from OUT ring in dom0, domU writes logs there */
static int read_from_ring(char *str, int len)
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

static void console_read_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	char buffer[128];
	int recv;
	printk("Starting read thread!\n");

	while (!console_thrd_stop) {
		memset(buffer, 0, sizeof(buffer));
		recv = read_from_ring(buffer, sizeof(buffer));
		if (recv) {
			printk("[domain hvc] %s", buffer);
		}
		k_sleep(K_MSEC(1000));
	}

	/* TODO: add memory freeing */
	printk("Exiting read thread!!!\n");
}

void start_domain_console(int domid)
{
	void *mapped_ring;
	xen_pfn_t ring_pfn, idx;
	int err, rc;

	mapped_ring = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	ring_pfn = virt_to_pfn(mapped_ring);
	idx = PHYS_PFN(GUEST_MAGIC_BASE) + CONSOLE_PFN_OFFSET;

	/* adding single page, but only xatpb can map with foreign domid */
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domid, XENMAPSPACE_gmfn_foreign,
				1, &idx, &ring_pfn, &err);
	printk("Return code for XENMEM_add_to_physmap_batch = %d, (console ring)\n", rc);

	intf = mapped_ring;

	read_tid = k_thread_create(&read_thrd, read_thrd_stack,
				K_KERNEL_STACK_SIZEOF(read_thrd_stack),
				console_read_thrd, NULL, NULL, NULL, 7, 0, K_NO_WAIT);
}

int domu_create(void)
{
	/* TODO: pass mem, domid etc. as parameters */
	int rc = 0;
	uint32_t domid = 1;
	struct xen_domctl_createdomain config;
	struct vcpu_guest_context vcpu_ctx;
	struct xen_domctl_scheduler_op sched_op;
	uint64_t base_addr = GUEST_RAM0_BASE;
	uint64_t base_pfn = PHYS_PFN(base_addr);
	uint64_t ventry;

	memset(&config, 0, sizeof(config));
	prepare_domain_cfg(&config);
	rc = xen_domctl_createdomain(domid, &config);
	printk("Return code = %d creation\n", rc);

	rc = xen_domctl_max_vcpus(domid, 1);
	printk("Return code = %d max_vcpus\n", rc);

	rc = xen_domctl_set_address_size(domid, 64);
	printk("Return code = %d set_address_size\n", rc);

	rc = xen_domctl_max_mem(domid, DOMU_MAXMEM_KB);

	/* TODO: fix mem amount here, some memory should left for populating magic pages */
	rc = prepare_domu_physmap(domid, base_pfn, DOMU_MAXMEM_KB/2);

	ventry = load_domu_image(domid, base_addr);

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	vcpu_ctx.user_regs.pc64 = ventry;
	vcpu_ctx.user_regs.cpsr = PSR_GUEST64_INIT;
	vcpu_ctx.sctlr = SCTLR_GUEST_INIT;
	vcpu_ctx.flags = VGCF_online;

	rc = xen_domctl_setvcpucontext(domid, 0, &vcpu_ctx);
	printk("Set VCPU context return code = %d\n", rc);

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	rc = xen_domctl_getvcpucontext(domid, 0, &vcpu_ctx);
	printk("Return code = %d getvcpucontext\n", rc);
	printk("VCPU PC = 0x%llx, x0 = 0x%llx, x1 = %llx\n",
		vcpu_ctx.user_regs.pc64, vcpu_ctx.user_regs.x0,
		vcpu_ctx.user_regs.x1);

	memset(&sched_op, 0, sizeof(sched_op));
	sched_op.sched_id = XEN_SCHEDULER_CREDIT2;
	sched_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

	rc = xen_domctl_scheduler_op(domid, &sched_op);
	printk("Return code = %d SCHEDOP_getinfo\n", rc);

	sched_op.u.credit2.cap = 0;
	sched_op.u.credit2.weight = 256;
	sched_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;

	rc = xen_domctl_scheduler_op(domid, &sched_op);
	printk("Return code = %d SCHEDOP_putinfo\n", rc);

	rc = xen_domctl_unpausedomain(domid);
	printk("Return code = %d XEN_DOMCTL_unpausedomain\n", rc);

	start_domain_console(domid);

	return rc;
}

int domu_destroy()
{
	/* TODO: pass domid as parameter */
	int rc;
	uint32_t domid = 1;

	console_thrd_stop = true;
	rc = xen_domctl_destroydomain(domid);
	printk("Return code = %d XEN_DOMCTL_destroydomain\n", rc);

	return rc;
}

void main(void) {
	/* Nothing to do on app start */
}
