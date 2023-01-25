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

Follow commands below to fetch, build and run zephyr under Xen hypervisor in emulated Cortex A53:

```
$: west init -m https://github.com/sa-kib/xenutils.git --mr xenutils_devel xephyr
$: cd xephyr
$: west update
$: west zephyr-export
$: cd xenutils
$: west build -b xenvm -p always
$: west build -t run
```

Also it is possible to build XenUtils via Zephyr Project Dockerimage. You need to perform all commands, except the last three,
they will be made inside Docker.
Steps:

Clone Dockerfiles from repo:
```
$: git clone https://github.com/zephyrproject-rtos/docker-image.git
```

Build Dockerimage:
```
$: cd docker-image
$: docker build -f Dockerfile.user --build-arg UID=$(id -u) --build-arg GID=$(id -g) -t zephyr-build:xenutils-image
```

Start Dockerimage and pass `projectdir` with already fetched sources (via `west update`) to Docker as volume:
```
$: docker run -ti -v ~/projectdir/:/workdir zephyr-build:xenutils-image
```

After this you will come to Docker shell and can run build cmds:
```
$: cd /workdir/xenutils/
$: source /workdir/zephyr_dom0/zephyr-env.sh
$: west build -b xenvm
```

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
