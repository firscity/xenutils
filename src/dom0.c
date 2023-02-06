/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/dom0/zimage.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/hvm.h>
#include <zephyr/xen/memory.h>
#include <zephyr/xen/public/hvm/hvm_op.h>
#include <zephyr/xen/public/hvm/params.h>
#include <zephyr/xen/public/domctl.h>
#include <zephyr/xen/public/xen.h>

#include <xen/public/io/console.h>
#include <xen/public/io/xs_wire.h>
#include <xen/events.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/shell/shell.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "domain.h"
#include "domain_configs/domd_config.h"
/*#include "domain_configs/domu_config.h"*/
#include "xss_message_handlers.h"
#include "xss_storage.h"
#include "xss_processing.h"

/* Number of active domains, used as an indicator to not exhaust allocated stack area.
 * This variable used during shell command execution, thus requires no sync. */
static int dom_num = 0;

#define DOMID_DOMD 1

static sys_dlist_t domain_list = SYS_DLIST_STATIC_INIT(&domain_list);
K_MUTEX_DEFINE(dl_mutex);

static void arch_prepare_domain_cfg(struct xen_domain_cfg *dom_cfg,
				    struct xen_arch_domainconfig *arch_cfg)
{
	int i;
	int max_irq = dom_cfg->nr_irqs ? dom_cfg->irqs[0] : 0;

	arch_cfg->gic_version = dom_cfg->gic_version;
	arch_cfg->tee_type = dom_cfg->tee_type;

	/*
	 * xen_arch_domainconfig 'nr_spis' should be >= than biggest
	 * absolute irq number.
	 */
	for (i = 1; i < dom_cfg->nr_irqs; i++) {
		if (max_irq < dom_cfg->irqs[i]) {
			max_irq = dom_cfg->irqs[i];
		}
	}
	arch_cfg->nr_spis = max_irq;
}

static void prepare_domain_cfg(struct xen_domain_cfg *dom_cfg,
			       struct xen_domctl_createdomain *create)
{
	create->flags = dom_cfg->flags;
	create->max_vcpus = dom_cfg->max_vcpus;
	create->max_evtchn_port = dom_cfg->max_evtchns;
	create->max_grant_frames = dom_cfg->gnt_frames;
	create->max_maptrack_frames = dom_cfg->max_maptrack_frames;

	arch_prepare_domain_cfg(dom_cfg, &create->arch);
}

static int allocate_domain_evtchns(struct xen_domain *domain)
{
	int rc;

	/* TODO: Alloc all required evtchns */
	rc = evtchn_alloc_unbound(domain->domid, DOMID_SELF);
	if (rc < 0) {
		printk("failed to alloc evtchn for domain #%d xenstore, rc = %d\n", domain->domid,
		       rc);
		return rc;
	}
	domain->xenstore_evtchn = rc;

	printk("Generated remote_domid=%d, xenstore_evtchn=%d\n", domain->domid,
	       domain->xenstore_evtchn);

	rc = evtchn_alloc_unbound(domain->domid, DOMID_SELF);
	if (rc < 0) {
		printk("failed to alloc evtchn for domain #%d console, rc = %d\n", domain->domid,
		       rc);
		return rc;
	}
	domain->console_evtchn = rc;

	printk("Generated remote_domid=%d, console evtchn=%d\n", domain->domid,
	       domain->console_evtchn);

	return 0;
}

static int allocate_magic_pages(int domid)
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
	mapped_base_pfn = PHYS_PFN((uint64_t)mapped_magic);
	for (i = 0; i < nr_exts; i++) {
		mapped_pfns[i] = mapped_base_pfn + i;
	}
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domid, XENMAPSPACE_gmfn_foreign, nr_exts,
					 extents, mapped_pfns, err_codes);

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

	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_PFN, domid, magic_base_pfn + CONSOLE_PFN_OFFSET);
	rc = hvm_set_parameter(HVM_PARAM_STORE_PFN, domid, magic_base_pfn + XENSTORE_PFN_OFFSET);

	return rc;
}

/* Xen can populate physmap with different extent size, we are using 4K and 2M */
#define EXTENT_2M_SIZE_KB 2048
#define EXTENT_2M_PFN_SHIFT 9
/* We need to populate magic pages and memory map here */
static int prepare_domu_physmap(int domid, uint64_t base_pfn, struct xen_domain_cfg *cfg)
{
	int i, rc;
	uint64_t nr_mem_exts = ceiling_fraction(cfg->mem_kb, EXTENT_2M_SIZE_KB);
	xen_pfn_t mem_extents[nr_mem_exts];

	allocate_magic_pages(domid);

	for (i = 0; i < nr_mem_exts; i++) {
		mem_extents[i] = base_pfn + (i << EXTENT_2M_PFN_SHIFT);
	}
	rc = xendom_populate_physmap(domid, EXTENT_2M_PFN_SHIFT, nr_mem_exts, 0, mem_extents);
	if (rc != nr_mem_exts) {
		printk("Error while populating %lld mem exts for domain#%d, rc = %d\n", nr_mem_exts,
		       domid, rc);
	}

	return 0;
}

extern char __img_domd_start[];
extern char __img_domd_end[];
extern char __img_domu_start[];
extern char __img_domu_end[];
uint64_t load_domd_image(int domid, uint64_t base_addr, const char *img_start, const char *img_end)
{
	int i, rc;
	void *mapped_domd;
	uint64_t mapped_base_pfn;
	uint64_t domd_size = img_end - img_start;
	uint64_t nr_pages = ceiling_fraction(domd_size, XEN_PAGE_SIZE);
	xen_pfn_t mapped_pfns[nr_pages];
	xen_pfn_t indexes[nr_pages];
	int err_codes[nr_pages];
	struct xen_domctl_cacheflush cacheflush;

	struct zimage64_hdr *zhdr = (struct zimage64_hdr *)img_start;
	uint64_t base_pfn = PHYS_PFN(base_addr);
	printk("Zimage header details: text_offset = %llx, base_addr = %llx, pages = %lld (size = %lld)\n", zhdr->text_offset,
	       base_addr, nr_pages, nr_pages * XEN_PAGE_SIZE);

	mapped_domd = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE * nr_pages);

	if (mapped_domd == NULL)
	{
		return NULL;
	}

	printk("Allocated %ld pages (%ld), mapped_domd=%p\n", nr_pages, XEN_PAGE_SIZE * nr_pages, mapped_domd);
	memset(mapped_domd, 0, XEN_PAGE_SIZE * nr_pages);
	printk("cleaned %ld pages\n", nr_pages);
	mapped_base_pfn = PHYS_PFN((uint64_t)mapped_domd);

	for (i = 0; i < nr_pages; i++) {
		mapped_pfns[i] = mapped_base_pfn + i;
		indexes[i] = base_pfn + i;
	}

	rc = xendom_add_to_physmap_batch(DOMID_SELF, domid, XENMAPSPACE_gmfn_foreign, nr_pages,
					 indexes, mapped_pfns, err_codes);
	printk("Return code for XENMEM_add_to_physmap_batch = %d\n", rc);
	printk("mapped_domd = %p\n", mapped_domd);
	printk("Zephyr DomD start addr = %p, end addr = %p, binary size = 0x%llx\n",
	       img_start, img_end, domd_size);

	/* Copy binary to domain pages and clear cache */
	memcpy(mapped_domd, img_start, domd_size);
	printk("Binary copied\n");

	cacheflush.start_pfn = mapped_base_pfn;
	cacheflush.nr_pfns = nr_pages;
	rc = xen_domctl_cacheflush(0, &cacheflush);
	printk("Return code for xen_domctl_cacheflush = %d\n", rc);

	/* Needed to remove mapped DomU pages from Dom0 physmap */
	for (i = 0; i < nr_pages; i++) {
		rc = xendom_remove_from_physmap(DOMID_SELF, mapped_pfns[i]);
	}

	/*
	 * After this Dom0 will have memory hole in mapped_domd address,
	 * needed to populate memory on this address before freeing.
	 */
	rc = xendom_populate_physmap(DOMID_SELF, 0, nr_pages, 0, mapped_pfns);
	printk(">>> Return code = %d XENMEM_populate_physmap\n", rc);

	k_free(mapped_domd);

	/* .text start address in domU memory */
	return base_addr + zhdr->text_offset;
}

/*extern char __dtb_domu_start[];
extern char __dtb_domu_end[];*/
extern char __dtb_domd_start[];
extern char __dtb_domd_end[];
void load_domd_dtb(int domid, uint64_t dtb_addr, const char *dtb_start, const char *dtb_end)
{
	int i, rc;
	void *mapped_dtb;
	uint64_t mapped_dtb_pfn, dtb_pfn = PHYS_PFN(dtb_addr);
	uint64_t dtb_size = dtb_end - dtb_start;
	uint64_t nr_pages = ceiling_fraction(dtb_size, XEN_PAGE_SIZE);
	xen_pfn_t mapped_pfns[nr_pages];
	xen_pfn_t indexes[nr_pages];
	int err_codes[nr_pages];
	struct xen_domctl_cacheflush cacheflush;

	mapped_dtb = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE * nr_pages);
	mapped_dtb_pfn = PHYS_PFN((uint64_t)mapped_dtb);

	for (i = 0; i < nr_pages; i++) {
		mapped_pfns[i] = mapped_dtb_pfn + i;
		indexes[i] = dtb_pfn + i;
	}

	rc = xendom_add_to_physmap_batch(DOMID_SELF, domid, XENMAPSPACE_gmfn_foreign, nr_pages,
					 indexes, mapped_pfns, err_codes);
	printk("Return code for XENMEM_add_to_physmap_batch = %d\n", rc);
	printk("mapped_dtb = %p\n", mapped_dtb);
	printk("U-Boot dtb start addr = %p, end addr = %p, binary size = 0x%llx\n", dtb_start,
	       dtb_end, dtb_size);
	printk("U-Boot dtb will be placed on addr = %p\n", (void *)dtb_addr);

	/* Copy binary to domain pages and clear cache */
	memcpy(mapped_dtb, dtb_start, dtb_size);

	cacheflush.start_pfn = mapped_dtb_pfn;
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

	k_free(mapped_dtb);
}

int share_domain_iomems(int domid, struct xen_domain_iomem *iomems, int nr_iomem)
{
	int i, rc = 0;

	for (i = 0; i < nr_iomem; i++) {
		rc = xen_domctl_iomem_permission(domid, iomems[i].first_mfn, iomems[i].nr_mfns, 1);
		if (rc) {
			printk("Failed to allow iomem access to mfn 0x%llx, err = %d\n",
			       iomems[i].first_mfn, rc);
		}

		if (!iomems[i].first_gfn) {
			/* Map to same location as machine frame number */
			rc = xen_domctl_memory_mapping(domid, iomems[i].first_mfn,
						       iomems[i].first_mfn, iomems[i].nr_mfns, 1);
		} else {
			/* Map to specified location */
			rc = xen_domctl_memory_mapping(domid, iomems[i].first_gfn,
						       iomems[i].first_mfn, iomems[i].nr_mfns, 1);
		}
		if (rc) {
			printk("Failed to map mfn 0x%llx, err = %d\n", iomems[i].first_mfn, rc);
		}
	}

	return rc;
}

int bind_domain_irqs(int domid, uint32_t *irqs, int nr_irqs)
{
	int i, rc = 0;

	for (i = 0; i < nr_irqs; i++) {
		rc = xen_domctl_bind_pt_irq(domid, irqs[i], PT_IRQ_TYPE_SPI, 0, 0, 0, 0, irqs[i]);
		if (rc) {
			printk("Failed to bind irq #%d, err = %d\n", irqs[i], rc);
			/*return rc;*/
		}
	}

	return rc;
}

int assign_dtdevs(int domid, char *dtdevs[], int nr_dtdevs)
{
	int i, rc = 0;

	for (i = 0; i < nr_dtdevs; i++) {
		rc = xen_domctl_assign_dt_device(domid, dtdevs[i]);
		if (rc) {
			printk("Failed to assign dtdev - %s, err = %d\n", dtdevs[i], rc);
			return rc;
		}
	}

	return rc;
}

int map_domain_xenstore_ring(struct xen_domain *domain)
{
	void *mapped_ring;
	xen_pfn_t ring_pfn, idx;
	int err, rc;
	struct xenstore_domain_interface *intf;

	mapped_ring = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	if (!mapped_ring) {
		printk("Failed to alloc memory for domain #%d console ring buffer\n",
		       domain->domid);
		return -ENOMEM;
	}

	memset(mapped_ring, 0, XEN_PAGE_SIZE);
	ring_pfn = virt_to_pfn(mapped_ring);
	idx = PHYS_PFN(GUEST_MAGIC_BASE) + XENSTORE_PFN_OFFSET;

	/* adding single page, but only xatpb can map with foreign domid */
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domain->domid, XENMAPSPACE_gmfn_foreign, 1,
					 &idx, &ring_pfn, &err);
	if (rc) {
		printk("Failed to map xenstore ring buffer of domain #%d - rc = %d\n",
		       domain->domid, rc);
		k_free(mapped_ring);
		return rc;
	}

	domain->domint = mapped_ring;
	intf = (struct xenstore_domain_interface *)domain->domint;
	intf->server_features = XENSTORE_SERVER_FEATURE_RECONNECTION;
	intf->connection = XENSTORE_CONNECTED;

	return 0;
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
	memset(mapped_ring, 0, XEN_PAGE_SIZE);
	idx = PHYS_PFN(GUEST_MAGIC_BASE) + CONSOLE_PFN_OFFSET;

	/* adding single page, but only xatpb can map with foreign domid */
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domain->domid, XENMAPSPACE_gmfn_foreign, 1,
					 &idx, &ring_pfn, &err);
	if (rc) {
		printk("Failed to map console ring buffer of domain #%d - rc = %d\n", domain->domid,
		       rc);
		return rc;
	}

	domain->intf = mapped_ring;

	return 0;
}

struct xen_domain *domid_to_domain(uint32_t domid)
{
	struct xen_domain *iter;

	SYS_DLIST_FOR_EACH_CONTAINER (&domain_list, iter, node) {
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

int domu_console_start(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	struct xen_domain *domain;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		shell_error(shell, "No domain with domid = %u is present\n", domid);
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
		shell_error(shell, "Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		shell_error(shell, "No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return stop_domain_console(domain);
}

void initialize_xenstore(uint32_t domid, const struct xen_domain_cfg *domcfg, const struct xen_domain *domain)
{
	char lbuffer[256] = { 0 };
	char rbuffer[256] = { 0 };
	char uuid[40];
	char basepref[] = "/local/domain";
	char *dirs[] = { "data",
			 "drivers",
			 "feature",
			 "attr",
			 "error",
			 "control",
			 "control/shutdown",
			 "control/feature-poweroff",
			 "control/feature-reboot",
			 "control/feature-suspend",
			 "control/sysrq",
			 "device/vbd",
			 "device/suspend/event-channel",
			 NULL };

	// TODO: generate properly
	snprintf(uuid, 40, "00000000-0000-0000-0000-%012d", domid);

	xss_do_write("/tool/xenstored", "");

	for (int i = 0; i < domcfg->max_vcpus; ++i) {
		sprintf(lbuffer, "%s/%d/cpu/%d/availability", basepref, domid, i);
		xss_do_write(lbuffer, "online");
	}

	sprintf(lbuffer, "%s/%d/memory/static-max", basepref, domid);
	sprintf(rbuffer, "%lld", domain->max_mem_kb);
	xss_do_write(lbuffer, rbuffer);
	sprintf(lbuffer, "%s/%d/memory/target", basepref, domid);
	xss_do_write(lbuffer, rbuffer);
	sprintf(lbuffer, "%s/%d/memory/videoram", basepref, domid);
	xss_do_write(lbuffer, "-1");
	sprintf(lbuffer, "%s/%d/control/platform-feature-multiprocessor-suspend", basepref, domid);
	xss_do_write(lbuffer, "1");
	sprintf(lbuffer, "%s/%d/control/platform-feature-xs_reset_watches", basepref, domid);
	xss_do_write(lbuffer, "1");

	sprintf(lbuffer, "%s/%d/vm", basepref, domid);
	xss_do_write(lbuffer, uuid);

	sprintf(lbuffer, "/vm/%s/name", uuid);
	sprintf(rbuffer, "zephyr-%d", domid);
	xss_do_write(lbuffer, rbuffer);
	sprintf(lbuffer, "/local/domain/%d/name", domid);
	xss_do_write(lbuffer, rbuffer);
	sprintf(lbuffer, "/vm/%s/start_time", uuid);
	xss_do_write(lbuffer, "0");
	sprintf(lbuffer, "/vm/%s/uuid", uuid);
	xss_do_write(lbuffer, uuid);

	sprintf(lbuffer, "%s/%d/domid", basepref, domid);
	sprintf(rbuffer, "%d", domid);
	xss_do_write(lbuffer, rbuffer);

	for (int i = 0; dirs[i]; ++i) {
		sprintf(lbuffer, "%s/%d/%s", basepref, domid, dirs[i]);
		xss_do_write(lbuffer, "");
	}

	sprintf(lbuffer, "/libxl/%d/dm-version", domid);
	xss_do_write(lbuffer, "qemu_xen_traditional");
	sprintf(lbuffer, "/libxl/%d/type", domid);
	xss_do_write(lbuffer, "pvh");
}

#define LOAD_ADDR_OFFSET 0x80000
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
	/* TODO: make it not hardcoded */
	uint64_t dtb_addr = GUEST_RAM0_BASE;
	uint64_t ventry;
	struct xen_domain *domain;
	struct xen_domain_cfg *domcfg;
	char *domdtdevs;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	if (dom_num >= DOM_MAX) {
		printk("Runtime exceeds maximum number of domains\n");
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		printk("Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	/*domcfg = (domid == DOMID_DOMD) ? &domd_cfg : &domu_cfg;
	domdtdevs = (domid == DOMID_DOMD) ? domd_dtdevs : domu_dtdevs;*/

	domcfg = &domd_cfg;
	domdtdevs = domd_dtdevs;

	memset(&config, 0, sizeof(config));
	prepare_domain_cfg(domcfg, &config);
	config.grant_opts = XEN_DOMCTL_GRANT_version(1);

	rc = xen_domctl_createdomain(domid, &config);
	printk("Return code = %d creation\n", rc);
	if (rc) {
		return rc;
	}

	domain = k_malloc(sizeof(*domain));
	__ASSERT(domain, "Can not allocate memory for domain struct");
	memset(domain, 0, sizeof(*domain));
	domain->domid = domid;

	rc = xen_domctl_max_vcpus(domid, domcfg->max_vcpus);
	printk("Return code = %d max_vcpus\n", rc);
	domain->num_vcpus = domcfg->max_vcpus;

	rc = xen_domctl_set_address_size(domid, 64);
	printk("Return code = %d set_address_size\n", rc);
	domain->address_size = 64;

	domain->max_mem_kb = domcfg->mem_kb + (domcfg->gnt_frames + NR_MAGIC_PAGES) * XEN_PAGE_SIZE;
	rc = xen_domctl_max_mem(domid, domain->max_mem_kb);

	/* Calculation according to xl.cfg manual for shadow memory (1MB/CPU + 8KB for every 1MB RAM */
	rc = xen_domctl_set_paging_mempool_size(domid, domcfg->max_vcpus * 1024 * 1024 + 8 * domcfg->mem_kb);
	printk("Return code = %d xen_domctl_set_paging_mempool_size\n", rc);

	rc = allocate_domain_evtchns(domain);
	printk("Return code = %d allocate_domain_evtchns\n", rc);

	rc = prepare_domu_physmap(domid, base_pfn, domcfg);

	if (domid == DOMID_DOMD) {
		ventry = load_domd_image(domid, base_addr + LOAD_ADDR_OFFSET, __img_domd_start, __img_domd_end);
		load_domd_dtb(domid, dtb_addr, __dtb_domd_start, __dtb_domd_end);
	} /*else {
		ventry = load_domd_image(domid, base_addr + LOAD_ADDR_OFFSET, __img_domu_start, __img_domu_end);
		load_domd_dtb(domid, dtb_addr, __dtb_domu_start, __dtb_domu_end);
	}*/

	if (ventry == NULL)
	{
		printk("Unable to load image, insufficient memory\n");
		return 10;
	}

	rc = share_domain_iomems(domid, domcfg->iomems, domcfg->nr_iomems);

	rc = bind_domain_irqs(domid, domcfg->irqs, domcfg->nr_irqs);

	rc = assign_dtdevs(domid, domdtdevs, domcfg->nr_dtdevs);

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	vcpu_ctx.user_regs.x0 = dtb_addr;
	vcpu_ctx.user_regs.pc64 = ventry;
	vcpu_ctx.user_regs.cpsr = PSR_GUEST64_INIT;
	vcpu_ctx.sctlr = SCTLR_GUEST_INIT;
	vcpu_ctx.flags = VGCF_online;

	rc = xen_domctl_setvcpucontext(domid, 0, &vcpu_ctx);
	printk("Set VCPU context return code = %d\n", rc);

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	rc = xen_domctl_getvcpucontext(domid, 0, &vcpu_ctx);
	printk("Return code = %d getvcpucontext\n", rc);
	printk("VCPU PC = 0x%llx, x0 = 0x%llx, x1 = %llx\n", vcpu_ctx.user_regs.pc64,
	       vcpu_ctx.user_regs.x0, vcpu_ctx.user_regs.x1);

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

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dnode_init(&domain->node);
	sys_dlist_append(&domain_list, &domain->node);
	k_mutex_unlock(&dl_mutex);

	rc = map_domain_xenstore_ring(domain);

	if (rc) {
		printk("Unable to map domain xenstore ring, rc=%d\n", rc);
		return rc;
	}

	rc = start_domain_stored(domain);
	if (rc) {
		return rc;
	}

	/* TODO: do this on console creation */
	rc = map_domain_console_ring(domain);
	printk("map domain ring OK\n");
	if (rc) {
		return rc;
	}

	/* TODO: for debug, remove this or set as optional */
	rc = init_domain_console(domain);

	if (rc) {
		printk("Unable to init domain console, rc=%d\n", rc);
		return rc;
	}

	rc = start_domain_console(domain);

	if (rc) {
		printk("Unable to start domain console, rc=%d\n", rc);
		return rc;
	}

	initialize_xenstore(domid, domcfg, domain);

	if (domid == DOMID_DOMD) {
		rc = xen_domctl_unpausedomain(domid);
		printk("Return code = %d XEN_DOMCTL_unpausedomain\n", rc);
	} else {
		printk("Created domain is paused\nTo unpause issue: xu unpause -d %d\n", domid);
	}

	++dom_num;

	return rc;
}

void unmap_domain_ring(void *p)
{
	xen_pfn_t ring_pfn = virt_to_pfn(p);
	int rc = xendom_remove_from_physmap(DOMID_SELF, ring_pfn);
	printk("Return code for xendom_remove_from_physmap = %d [%08p]\n", rc, p);

	rc = xendom_populate_physmap(DOMID_SELF, 0, 1, 0, &ring_pfn);
	printk("Return code for xendom_populate_physmap = %d [%08p]\n", rc, p);

	k_free(p);
}

int domu_destroy(const struct shell *shell, size_t argc, char **argv)
{
	int rc;
	uint32_t domid = 0;
	struct xen_domain *domain = NULL;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		shell_error(shell, "No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	stop_domain_stored(domain);
	/* TODO: do this on console destroying */
	stop_domain_console(domain);

	unmap_domain_ring(domain->intf);
	unmap_domain_ring(domain->domint);

	rc = xen_domctl_destroydomain(domid);
	shell_print(shell, "Return code = %d XEN_DOMCTL_destroydomain\n", rc);

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dlist_remove(&domain->node);
	k_mutex_unlock(&dl_mutex);

	k_free(domain);

	--dom_num;

	return rc;
}

int domu_pause(const struct shell *shell, size_t argc, char **argv)
{
	int rc;
	uint32_t domid = 0;
	struct xen_domain *domain = NULL;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
	if (!domain) {
		shell_error(shell, "No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	rc = xen_domctl_pausedomain(domid);

	return rc;
}

int domu_unpause(const struct shell *shell, size_t argc, char **argv)
{
	int rc;
	uint32_t domid = 0;
	struct xen_domain *domain = NULL;

	if (argc < 3 || argc > 4) {
		return -EINVAL;
	}

	domid = parse_domid(argc, argv);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to unpause cmd\n");
		return -EINVAL;
	}

	shell_print(shell, "domid=%d\n", domid);

	domain = domid_to_domain(domid);
	if (!domain) {
		shell_error(shell, "No domain with domid = %u is present\n", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	rc = xen_domctl_unpausedomain(domid);

	return rc;
}

void main(void)
{
	/* HACK */
	char *argv[] = {"", "-d", "1"};

	init_root();
	domu_create(NULL, 3, argv);
}
