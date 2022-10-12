#include <shell/shell.h>

extern int domu_console_start(const struct shell *shell, size_t argc, char **argv);
extern int domu_console_stop(const struct shell *shell, size_t argc, char **argv);
extern int domu_create(const struct shell *shell, size_t argc, char **argv);
extern int domu_destroy(const struct shell *shell, size_t argc, char **argv);
extern int domu_pause(const struct shell *shell, size_t argc, char **argv);
extern int domu_unpause(const struct shell *shell, size_t argc, char **argv);

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xu,
	SHELL_CMD_ARG(create, NULL,
		      " Create Xen domain\n"
		      " Usage: create -d <domid>\n",
		      domu_create, 3, 0),
	SHELL_CMD_ARG(destroy, NULL,
		      " Destroy Xen domain\n"
		      " Usage: destroy -d <domid>\n",
		      domu_destroy, 3, 0),
	SHELL_CMD_ARG(console_start, NULL,
		      " Start console thread for Xen domain\n"
		      " Only single thread and only output is currently supported\n"
		      " Usage: console_start -d <domid>\n",
		      domu_console_start, 3, 0),
	SHELL_CMD_ARG(console_stop, NULL,
		      " Stop console thread for Xen domain\n"
		      " Usage: console_stop -d <domid>\n",
		      domu_console_stop, 3, 0),
	SHELL_CMD_ARG(pause, NULL,
		      " Pause Xen domain\n"
		      " Usage: pause -d <domid>\n",
		      domu_pause, 3, 0),
	SHELL_CMD_ARG(unpause, NULL,
		      " Unpause Xen domain\n"
		      " Usage: unpause -d <domid>\n",
		      domu_unpause, 3, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xu, &subcmd_xu, "Xenutils commands", NULL, 2, 0);
