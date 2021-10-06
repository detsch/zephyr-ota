/*
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __AKNANO_JSON_H__
#define __AKNANO_JSON_H__

#include <data/json.h>


struct aknano_target_custom_parsed {
	char *hardwareIds[10];
	size_t hardwareIds_len;
	const char *name;
	char *tags[10];
	size_t tags_len;
	const char *targetFormat;
	const char *updatedAt;
	const char *uri;
	const char *version;
};

struct aknano_target_hashes_parsed {
	char *sha256;
};

struct aknano_target_parsed {
	struct aknano_target_hashes_parsed hashes;
	struct aknano_target_custom_parsed custom;
	int length;
};


const struct json_obj_descr json_aknano_target_hashes_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct aknano_target_hashes_parsed, sha256, JSON_TOK_STRING),
};

const struct json_obj_descr json_aknano_target_custom_descr[] = {
	JSON_OBJ_DESCR_ARRAY_NAMED(struct aknano_target_custom_parsed, "tags",
				tags, 10, tags_len,
				JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct aknano_target_custom_parsed, name, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_NAMED(struct aknano_target_custom_parsed, "hardwareIds",
				hardwareIds, 10, hardwareIds_len,
				JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct aknano_target_custom_parsed, targetFormat, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct aknano_target_custom_parsed, updatedAt, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct aknano_target_custom_parsed, uri, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct aknano_target_custom_parsed, version, JSON_TOK_STRING),
};


const struct json_obj_descr json_aknano_target_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct aknano_target_parsed, hashes, json_aknano_target_hashes_descr),
	JSON_OBJ_DESCR_OBJECT(struct aknano_target_parsed, custom, json_aknano_target_custom_descr),
	JSON_OBJ_DESCR_PRIM(struct aknano_target_parsed, length, JSON_TOK_NUMBER),
};


#endif
