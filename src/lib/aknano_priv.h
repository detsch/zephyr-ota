/*
 * Copyright (c) 2020 Linumiz
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *
 * @brief This file contains structures representing JSON messages
 * exchanged with a hawkbit
 */

#ifndef __AKNANO_PRIV_H__
#define __AKNANO_PRIV_H__

#include <data/json.h>

#define AKNANO_SLEEP_LENGTH 8

enum aknano_http_request {
	AKNANO_PROBE,
	AKNANO_CONFIG_DEVICE,
	AKNANO_CLOSE,
	AKNANO_PROBE_DEPLOYMENT_BASE,
	AKNANO_REPORT,
	AKNANO_DOWNLOAD,
};

enum aknano_status_fini {
	AKNANO_STATUS_FINISHED_SUCCESS,
	AKNANO_STATUS_FINISHED_FAILURE,
	AKNANO_STATUS_FINISHED_NONE,
};

enum aknano_status_exec {
	AKNANO_STATUS_EXEC_CLOSED = 0,
	AKNANO_STATUS_EXEC_PROCEEDING,
	AKNANO_STATUS_EXEC_CANCELED,
	AKNANO_STATUS_EXEC_SCHEDULED,
	AKNANO_STATUS_EXEC_REJECTED,
	AKNANO_STATUS_EXEC_RESUMED,
	AKNANO_STATUS_EXEC_NONE,
};

enum aknano_dev_acid_t {
	AKNANO_ACTION_ID_CURRENT = 0,
	AKNANO_ACTION_ID_UPDATE,
};

struct aknano_href {
	const char *href;
};

struct aknano_status_result {
	const char *finished;
};

struct aknano_status {
	struct aknano_status_result result;
	const char *execution;
};

struct aknano_ctl_res_sleep {
	const char *sleep;
};

struct aknano_ctl_res_polling {
	struct aknano_ctl_res_sleep polling;
};

struct aknano_ctl_res_links {
	struct aknano_href deploymentBase;
	struct aknano_href configData;
	struct aknano_href cancelAction;
};

struct aknano_ctl_res {
	struct aknano_ctl_res_polling config;
	struct aknano_ctl_res_links _links;
};

struct aknano_cfg_data {
	const char *VIN;
	const char *hwRevision;
};

struct aknano_cfg {
	const char *mode;
	struct aknano_cfg_data data;
	const char *id;
	const char *time;
	struct aknano_status status;
};

struct aknano_close {
	char *id;
	const char *time;
	struct aknano_status status;
};

/* Maximum number of chunks we support */
#define AKNANO_DEP_MAX_CHUNKS 1
/* Maximum number of artifacts per chunk. */
#define AKNANO_DEP_MAX_CHUNK_ARTS 1

struct aknano_dep_res_hashes {
	const char *sha1;
	const char *md5;
	const char *sha256;
};

struct aknano_dep_res_links {
	struct aknano_href download_http;
	struct aknano_href md5sum_http;
};

struct aknano_dep_res_arts {
	const char *filename;
	struct aknano_dep_res_hashes hashes;
	struct aknano_dep_res_links _links;
	int size;
};

struct aknano_dep_res_chunk {
	const char *part;
	const char *name;
	const char *version;
	struct aknano_dep_res_arts artifacts[AKNANO_DEP_MAX_CHUNK_ARTS];
	size_t num_artifacts;
};

struct aknano_dep_res_deploy {
	const char *download;
	const char *update;
	struct aknano_dep_res_chunk chunks[AKNANO_DEP_MAX_CHUNKS];
	size_t num_chunks;
};

struct aknano_dep_res {
	const char *id;
	struct aknano_dep_res_deploy deployment;
};

struct aknano_dep_fbk {
	const char *id;
	struct aknano_status status;
};

struct aknano_cancel {
	struct aknano_href cancelBase;
};

struct entry {
	char *http_req_str;
	int n;
};

struct entry aknano_http_request[] = {
	{"AKNANO_PROBE", 0},
	{"AKNANO_CONFIG_DEVICE", 1},
	{"AKNANO_CLOSE", 2},
	{"AKNANO_PROBE_DEPLOYMENT_BASE", 3},
	{"AKNANO_REPORT", 4},
	{"AKNANO_DOWNLOAD", 5},
};

#endif /* __AKNANO_PRIV_H__ */
