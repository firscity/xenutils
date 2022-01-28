#include <xen/generic.h>

struct domain_console {

};

struct xen_domain {
	uint32_t domid;
	struct xencons_interface *intf;
	int num_vcpus;
	int address_size;
	uint64_t max_mem_kb;
	sys_dnode_t node;
};
