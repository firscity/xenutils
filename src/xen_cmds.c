#include <shell/shell.h>


extern int domu_create();
extern int domu_destroy();

SHELL_CMD_REGISTER(create_domu, NULL, "Create instance of Zephyr unprivilaged domain", domu_create);
SHELL_CMD_REGISTER(destroy_domu, NULL, "Destroy instance of Zephyr unprivilaged domain", domu_destroy);
