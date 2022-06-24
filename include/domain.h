#ifndef XENUTILS_DOMAIN_H
#define XENUTILS_DOMAIN_H

#include <xen/events.h>
#include <xen/generic.h>


struct xen_domain_iomem {
	/* where to map, if 0 - map to same place as mfn */
	uint64_t first_gfn;
	/* what to map */
	uint64_t first_mfn;
	/* how much frames to map */
	uint64_t nr_mfns;
};

struct xen_domain_cfg {
	uint64_t mem_kb;

	uint32_t flags;
	uint32_t max_vcpus;
	uint32_t max_evtchns;
	int32_t gnt_frames;
	int32_t max_maptrack_frames;

	/* ARM arch related */
	uint8_t gic_version;
	uint16_t tee_type;

	/* For peripheral sharing*/
	struct xen_domain_iomem *iomems;
	uint32_t nr_iomems;

	uint32_t *irqs;
	uint32_t nr_irqs;

	char **dtdevs;
	uint32_t nr_dtdevs;
};

struct xen_domain {
	uint32_t domid;
	struct xencons_interface *intf;
	int num_vcpus;
	int address_size;
	uint64_t max_mem_kb;
	sys_dnode_t node;
	evtchn_port_t console_evtchn;
	evtchn_port_t xenbus_evtchn;
};

#endif /* XENUTILS_DOMAIN_H */
