# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(xenutils)

include_directories(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_sources_ifdef(CONFIG_XEN_INITIAL_DOMAIN app PRIVATE src/xen_cmds.c src/dom0.c src/console_util.c src/xen_bus.c src/uboot_domu.S)

