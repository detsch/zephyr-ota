/*
 * Copyright (c) 2020 Linumiz
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __AKNANO_FIRMWARE_H__
#define __AKNANO_FIRMWARE_H__

#include <drivers/flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>

bool aknano_get_firmware_version(char *version, int version_len);

#endif /* __AKNANO_FIRMWARE_H__ */
