/*
 * Copyright (c) 2020 Linumiz
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @brief Aktualizr-nano Firmware Over-the-Air for Zephyr Project.
 * @defgroup aknano Aktualizr-nano Firmware Over-the-Air
 * @ingroup lib
 * @{
 */
#ifndef __AKNANO_H__
#define __AKNANO_H__

#define AKNANO_JSON_URL "/default/controller/v1"

/**
 * @brief Response message from Aktualizr-nano.
 *
 * @details These messages are used to inform the server and the
 * user about the process status of the Aktualizr-nano and also
 * used to standardize the errors that may occur.
 *
 */
enum aknano_response {
	AKNANO_NETWORKING_ERROR,
	AKNANO_UNCONFIRMED_IMAGE,
	AKNANO_METADATA_ERROR,
	AKNANO_DOWNLOAD_ERROR,
	AKNANO_OK,
	AKNANO_UPDATE_INSTALLED,
	AKNANO_NO_UPDATE,
	AKNANO_CANCEL_UPDATE,
};

/**
 * @brief Init the flash partition
 *
 * @return 0 on success, negative on error.
 */
int aknano_init(void);

/**
 * @brief Runs Aktualizr-nano probe and Hawkbit Aktualizr-nano automatically
 *
 * @details The aknano_autohandler handles the whole process
 * in pre-determined time intervals.
 */
void aknano_autohandler(void);

/**
 * @brief The Aktualizr-nano probe verify if there is some update to be 
 * performed.
 *
 * @return AKNANO_UPDATE_INSTALLED has an update available.
 * @return AKNANO_NO_UPDATE no update available.
 * @return AKNANO_NETWORKING_ERROR fail to connect to the Hawkbit server.
 * @return AKNANO_METADATA_ERROR fail to parse or to encode the metadata.
 * @return AKNANO_OK if success.
 * @return AKNANO_DOWNLOAD_ERROR faile while downloading the update package.
 */
enum aknano_response aknano_probe(void);

/**
 * @}
 */

#endif /* _AKNANO_H_ */
