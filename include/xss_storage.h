#ifndef XENBUS_STORAGE_H
#define XENBUS_STORAGE_H

struct xs_entry {
	char *key;
	char *value;
	sys_dlist_t child_list;

	sys_dnode_t node;
};

struct watch_entry {
	char *key;
	char *token;
	int domid;
	bool is_relative;

	sys_dnode_t node;
};

struct pending_watch_event_entry {
	char *key;
	int domid;

	sys_dnode_t node;
};

#endif
