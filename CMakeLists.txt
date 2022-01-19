# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(xenutils)

target_sources(app PRIVATE src/main.c src/test_module.c)
target_sources_ifdef(CONFIG_SHELL_BACKEND_SERIAL app PRIVATE src/uart_reinit.c)
target_sources_ifdef(CONFIG_XEN_INITIAL_DOMAIN app PRIVATE src/xen_cmds.c dom0/dom0.c)
