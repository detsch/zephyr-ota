/*
 * Copyright (c) 2020 Linumiz
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identiier: Apache-2.0
 */

#ifndef __AKNANO_DEVICE_H__
#define __AKNANO_DEVICE_H__

#include <zephyr.h>
#include <drivers/hwinfo.h>

#define DEVICE_ID_BIN_MAX_SIZE	16
#define DEVICE_ID_HEX_MAX_SIZE	((DEVICE_ID_BIN_MAX_SIZE * 2) + 1)

bool aknano_get_device_identity(char *id, int id_max_len);

#endif /* __AKNANO_DEVICE_H__ */
