# XenUtils project

---
## Overview
This project contains different Xen Domain 0 services required for domain management in Zephyr. Currently it has Zephyr shell with few commands united under "xu" group. It is possible to create
few instances of unprivilaged Zephyr domains (binary located in `include/domain_bins` directory), read their console output and destroy them.

Project is under development and supported only for Renesas H3 hardware with Xen 4.16 hypervisor. All updates will be shared on firscity/xenutils repo.

---
## Build
To fetch and build this project few steps are required.

First of all you need to pass Zephyr RTOS [getting started guide](https://docs.zephyrproject.org/latest/getting_started/index.html) and install mentioned dependencies and SDK.

Then you need to fetch this repo to separate directory in you workdir (please note, that Zephyr metatool west will fetch all project dependencies to upper directory):
```
$: cd ~/
$: mkdir projectdir   # project dependencies will be located here, e.g. west will copy specific Zephyr snapshot in here
$: cd projectdir/
$: git clone https://github.com/firscity/xenutils.git
$: cd xenutils/
```
Now you need to initialize west metatool with project manifest:
```
$: west init -l
```

To verify that everithing is OK you can check projects list:
```
$: west list
manifest     xenutils            HEAD                      N/A
zephyr_dom0  zephyr_dom0         dom0_demo_devel           https://github.com/firscity//zephyr.git
```

Now it is possible to fetch project dependencies (also this can be performed everytime when you want to get all updates in manifest projects):
```
$: west update
```

After successful fetch you `projectdir` will look like this:
```
$: ls ~/projectdir/
xenutils  zephyr_dom0
```

Now it is possible to start project build:
```
$: cd ~/projectdir/xenutils/
$: west build -b xenvm
```

After successful build Zephyr RTOS binary will be located in `~/projectdir/xenutils/build/zephyr` directory (`zephyr.bin`). You need to pass it to Xen as Domain 0.

---

## Available shell cmds
To create unprivilaged domain please run following cmd in Zephyr shell (automatic domid selection is not currently supported, it is possible to create multiple domains, just use different domid's):
```
 $: xu create -d <domid>
```

To start thread, that will fetch all output logs from created domain please run:
```
$: xu console_start -d <domid>
```

To stop console thread use (only single thread is supported, no need to specify domid):
```
$: xu console_stop
```

To destroy domain use:
```
$: xu destroy -d <domid>
```