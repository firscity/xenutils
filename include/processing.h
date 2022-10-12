#ifndef XENBUS_PROCESSING_H
#define XENBUS_PROCESSING_H

void xenbus_evt_thrd(void *p1, void *p2, void *p3);
int start_domain_stored(struct xen_domain *domain);
int stop_domain_stored(struct xen_domain *domain);

#define DOM_MAX 4

#endif
