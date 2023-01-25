# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(xenutils)

include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_sources_ifdef(CONFIG_XEN_INITIAL_DOMAIN app PRIVATE src/xen_cmds.c src/dom0.c src/console_util.c src/xen_bus.c src/uboot_domu.S)

include(ExternalProject)
set(XEN_SRCDIR ${CMAKE_CURRENT_SOURCE_DIR}/../xen)
set(XEN_BINDIR ${CMAKE_CURRENT_BINARY_DIR}/hyp)

ExternalProject_Add(
   hypervisor
   PREFIX ${XEN_BINDIR}
   SOURCE_DIR ${XEN_SRCDIR}/xen
   BINARY_DIR ${XEN_BINDIR}
   CONFIGURE_COMMAND ""
   BUILD_COMMAND ${MAKE} make -C ${XEN_SRCDIR}/xen O=${XEN_BINDIR}
      CONFIG_QEMU_XEN=y CONFIG_DEBUG=y XSM_ENABLE=y
      XEN_TARGET_ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- HOSTCC=gcc
  INSTALL_COMMAND cp ${XEN_BINDIR}/xen ${ZEPHYR_BINARY_DIR}/xen
)

add_dependencies(app hypervisor)
