# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

# This application has its own Kconfig options.
set(KCONFIG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/Kconfig)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(download_image)

target_sources(app PRIVATE src/main.c)
target_sources(app PRIVATE src/lib/aknano.c)
target_sources(app PRIVATE src/lib/aknano_device.c)
target_sources(app PRIVATE src/lib/aknano_firmware.c)

target_sources(app PRIVATE src/mqtt_publisher.c)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

generate_inc_file_for_target(
    app
    src/lib/https-cert.der
    ${gen_dir}/https-cert.der.inc
    )
