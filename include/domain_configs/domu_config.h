#ifndef XENUTILS_DOMU_CONFIG_H
#define XENUTILS_DOMU_CONFIG_H

#include <xen/generic.h>
#include <domain.h>

/* Please, keep this define in sync with number of dtdev entries */
#define NR_DOMU_DTDEVS 0
static char *domu_dtdevs[] = { };

static struct xen_domain_iomem domu_iomems[] = {

	{ .first_mfn = 0xe6060, .nr_mfns = 0x1},	/* PFC */
	{ .first_mfn = 0xe6150, .nr_mfns = 0x1},	/* CPG */
	{ .first_mfn = 0xe6160, .nr_mfns = 0x1},	/* RST */
	{ .first_mfn = 0xe6e68, .nr_mfns = 0x1},	/* SCIF1 */
};

static uint32_t domu_irqs[] = {
	/* serial@e6e68000 */
	185,
	/* serial@e6550000 */
	187,
};

struct xen_domain_cfg domu_cfg = {
	.mem_kb = 2097152,

	.flags = (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap | XEN_DOMCTL_CDF_iommu),
	.max_evtchns = 10,
	.max_vcpus = 4,
	.gnt_frames = 32,
	.max_maptrack_frames = 1,

	.iomems = domu_iomems,
	.nr_iomems = sizeof(domu_iomems) / sizeof(*domu_iomems),

	.irqs = domu_irqs,
	.nr_irqs = sizeof(domu_irqs) / sizeof(*domu_irqs),

	.gic_version = XEN_DOMCTL_CONFIG_GIC_V2,
	.tee_type = XEN_DOMCTL_CONFIG_TEE_NONE,

	.dtdevs = domu_dtdevs,
	.nr_dtdevs = NR_DOMU_DTDEVS,
};

#endif /* XENUTILS_DOMU_CONFIG_H */
