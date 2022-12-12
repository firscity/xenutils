#ifndef XENBUS_MESSAGE_HANDLERS_H
#define XENBUS_MESSAGE_HANDLERS_H

void handle_control(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_get_perms(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_set_perms(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_reset_watches(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_directory(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_read(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_write(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_mkdir(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_rm(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_watch(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_unwatch(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_transaction_start(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_transaction_stop(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);
void handle_get_domain_path(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len);

#endif
