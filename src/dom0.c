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

#include "domain.h"

#include <init.h>
#include <kernel.h>
#include <shell/shell.h>
#include <stdlib.h>
#include <string.h>

/* TODO: this should be read from some "config" */
#define DOMU_FLAGS		(XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap)
#define DOMU_MAX_VCPUS		1
#define DOMU_MAX_EVTCHN		10
#define DOMU_MAX_GNT_FRAMES	1
#define DOMU_MAX_MAPTRCK_FR	1

#define ARCH_DOMU_NR_SPIS	0

#define DOMU_MAXMEM_KB		65536

static sys_dlist_t domain_list = SYS_DLIST_STATIC_INIT(&domain_list);

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

int map_domain_console_ring(struct xen_domain *domain)
{
	void *mapped_ring;
	xen_pfn_t ring_pfn, idx;
	int err, rc;

	mapped_ring = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	if (!mapped_ring) {
		printk("Failed to alloc memory for domain #%d console ring buffer\n",
			domain->domid);
		return -ENOMEM;
	}

	ring_pfn = virt_to_pfn(mapped_ring);
	idx = PHYS_PFN(GUEST_MAGIC_BASE) + CONSOLE_PFN_OFFSET;

	/* adding single page, but only xatpb can map with foreign domid */
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domain->domid, XENMAPSPACE_gmfn_foreign,
				1, &idx, &ring_pfn, &err);
	if (rc) {
		printk("Failed to map console ring buffer of domain #%d - rc = %d\n",
			domain->domid, rc);
		return rc;
	}

	domain->intf = mapped_ring;

	return 0;
}

struct xen_domain * domid_to_domain(uint32_t domid)
{
	struct xen_domain *iter;

	SYS_DLIST_FOR_EACH_CONTAINER(&domain_list, iter, node) {
		if (iter->domid == domid) {
			return iter;
		}
	}

	return NULL;
}

uint32_t parse_domid(size_t argc, char **argv)
{
	/* first would be the cmd name, start from second */
	int pos = 1;

	if (argv[pos][0] == '-' && argv[pos][1] == 'd') {
		/* Take next value after "-d" option */
		pos++;
		return atoi(argv[pos]);
	}

	/* Use zero as invalid value */
	return 0;
}

extern int start_domain_console(struct xen_domain *domain);
extern int stop_domain_console(struct xen_domain *domain);

int domu_console_start(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	struct xen_domain *domain;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		printk("Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		printk("No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return start_domain_console(domain);
}
int domu_console_stop(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	struct xen_domain *domain;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		printk("Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		printk("No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return stop_domain_console(domain);
}
int domu_create(const struct shell *shell, size_t argc, char **argv)
{
	/* TODO: pass mem, domid etc. as parameters */
	int rc = 0;
	uint32_t domid = 0;
	struct xen_domctl_createdomain config;
	struct vcpu_guest_context vcpu_ctx;
	struct xen_domctl_scheduler_op sched_op;
	uint64_t base_addr = GUEST_RAM0_BASE;
	uint64_t base_pfn = PHYS_PFN(base_addr);
	uint64_t ventry;
	struct xen_domain *domain;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		printk("Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	memset(&config, 0, sizeof(config));
	prepare_domain_cfg(&config);
	rc = xen_domctl_createdomain(domid, &config);
	printk("Return code = %d creation\n", rc);
	if (rc) {
		return rc;
	}

	domain = k_malloc(sizeof(*domain));
	__ASSERT(domain, "Can not allocate memory for domain struct");
	memset(domain, 0, sizeof(*domain));
	domain->domid = domid;
	sys_dnode_init(&domain->node);

	rc = xen_domctl_max_vcpus(domid, DOMU_MAX_VCPUS);
	printk("Return code = %d max_vcpus\n", rc);
	domain->num_vcpus = DOMU_MAX_VCPUS;

	rc = xen_domctl_set_address_size(domid, 64);
	printk("Return code = %d set_address_size\n", rc);
	domain->address_size = 64;

	rc = xen_domctl_max_mem(domid, DOMU_MAXMEM_KB);
	domain->max_mem_kb = DOMU_MAXMEM_KB;

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

	/* TODO: lock here? */
	sys_dlist_append(&domain_list, &domain->node);
	rc = xen_domctl_unpausedomain(domid);
	printk("Return code = %d XEN_DOMCTL_unpausedomain\n", rc);

	/* TODO: do this on console creation */
	rc = map_domain_console_ring(domain);
	printk("map domain ring OK\n");
	if (rc) {
		return rc;
	}

	return rc;
}

int domu_destroy(const struct shell *shell, size_t argc, char **argv)
{
	int rc;
	uint32_t domid = 0;
	xen_pfn_t ring_pfn;
	struct xen_domain *domain = NULL;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		printk("Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		printk("No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	/* TODO: do this on console destroying */
	ring_pfn = virt_to_pfn(domain->intf);
	rc = xendom_remove_from_physmap(DOMID_SELF, ring_pfn);
	printk("Return code for xendom_remove_from_physmap = %d, (console ring)\n", rc);

	rc = xendom_populate_physmap(DOMID_SELF, 0, 1, 0, &ring_pfn);
	printk("Return code for xendom_populate_physmap = %d, (console ring)\n", rc);

	k_free(domain->intf);

	rc = xen_domctl_destroydomain(domid);
	printk("Return code = %d XEN_DOMCTL_destroydomain\n", rc);

	sys_dlist_remove(&domain->node);
	k_free(domain);

	return rc;
}

void main(void) {
	/* Nothing to do on app start */
}
