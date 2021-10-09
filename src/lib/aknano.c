/*
 * Copyright (c) 2016-2017 Linaro Limited
 * Copyright (c) 2018 Open Source Foundries Limited
 * Copyright (c) 2018 Foundries.io
 * Copyright (c) 2020 Linumiz
 * Copyright (c) 2021 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(aknano);

#include <stdio.h>
#include <zephyr.h>
#include <string.h>
#include <stdlib.h>
#include <data/json.h>
#include <net/net_ip.h>
#include <net/socket.h>
#include <net/net_mgmt.h>
#include <sys/reboot.h>
#include <drivers/flash.h>
#include <net/http_client.h>
#include <net/dns_resolve.h>
#include <logging/log_ctrl.h>
#include <storage/flash_map.h>

#include "aknano.h"
#include "aknano_json.h"
#include "aknano_priv.h"
#include "aknano_device.h"
#include "aknano_firmware.h"
#include "aknano_json.h"


#define CA_CERTIFICATE_TAG 1
#include <net/tls_credentials.h>
#include "ca_certificate.h"

/* #define AK_NANO_DRY_RUN */

#define ADDRESS_ID 1

#define CANCEL_BASE_SIZE 50
#define RECV_BUFFER_SIZE 640
#define URL_BUFFER_SIZE 300
#define STATUS_BUFFER_SIZE 200
#define DOWNLOAD_HTTP_SIZE 200
#define DEPLOYMENT_BASE_SIZE 50
#define RESPONSE_BUFFER_SIZE 1100

#define AKNANO_JSON_BUFFER_SIZE 1024
#define NETWORK_TIMEOUT (2 * MSEC_PER_SEC)
#define AKNANO_RECV_TIMEOUT (300 * MSEC_PER_SEC)

#define AKNANO_MAX_TAG_LENGTH 30
#define AKNANO_MAX_UPDATE_AT_LENGTH 30
#define AKNANO_MAX_URI_LENGTH 120

#define SLOT1_SIZE FLASH_AREA_SIZE(image_1)
#define HTTP_HEADER_CONTENT_TYPE_JSON "application/json;charset=UTF-8"

#define AKNANO_JSON_URL "/default/controller/v1"


#if ((CONFIG_AKNANO_POLL_INTERVAL > 1)	\
	&& (CONFIG_AKNANO_POLL_INTERVAL < 43200))
static uint32_t poll_sleep = (CONFIG_AKNANO_POLL_INTERVAL * 60 * MSEC_PER_SEC);
#else
static uint32_t poll_sleep = (300 * MSEC_PER_SEC);
#endif

/*
 "hardwareIds": [ "imx8mmevk" ],
 "name": "imx8mmevk-lmp",
 "tags": [    "devel",     "test" ],
 "targetFormat": "BINARY",
 "updatedAt": "2020-09-23T20:22:19Z",
 "uri": "https://ci.foundries.io/projects/hashcode/lmp/builds/120/zephyr.bin",
 "version": "120"
*/

struct aknano_target {
	char updatedAt[AKNANO_MAX_UPDATE_AT_LENGTH];
	char uri[AKNANO_MAX_URI_LENGTH];
	int32_t version;
};


struct aknano_json_data {
	size_t offset;
	uint8_t data[AKNANO_JSON_BUFFER_SIZE];
	struct aknano_target selected_target;
};

struct aknano_download {
	int download_status;
	int download_progress;
	size_t downloaded_size;
	size_t http_content_size;
};

static struct aknano_context {
	int sock;
	int32_t action_id;
	uint8_t *response_data;
	struct aknano_json_data aknano_json_data;
	int32_t json_action_id;
	struct k_sem semaphore;
	size_t url_buffer_size;
	size_t status_buffer_size;
	struct aknano_download dl;
	struct http_request http_req;
	struct flash_img_context flash_ctx;
	uint8_t url_buffer[URL_BUFFER_SIZE];
	uint8_t status_buffer[STATUS_BUFFER_SIZE];
	uint8_t recv_buf_tcp[RECV_BUFFER_SIZE];
	enum aknano_response code_status;
} hb_context;

static union {
	struct aknano_dep_res dep;
	struct aknano_ctl_res base;
	struct aknano_cancel cancel;
} aknano_results;

static struct k_work_delayable aknano_work_handle;

static int setup_socket(sa_family_t family, const char *server, int port,
			int *sock, struct sockaddr *addr, socklen_t addr_len)
{
	const char *family_str = family == AF_INET ? "IPv4" : "IPv6";
	int ret = 0;

	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS)) {
		sec_tag_t sec_tag_list[] = {
			CA_CERTIFICATE_TAG,
		};

		*sock = socket(family, SOCK_STREAM, IPPROTO_TLS_1_2);
		if (*sock >= 0) {
			ret = setsockopt(*sock, SOL_TLS, TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list));
			if (ret < 0) {
				LOG_ERR("Failed to set %s secure option (%d)",
					family_str, -errno);
				ret = -errno;
			}

			ret = setsockopt(*sock, SOL_TLS, TLS_HOSTNAME,
					 TLS_PEER_HOSTNAME,
			       sizeof(TLS_PEER_HOSTNAME));
			if (ret < 0) {
				LOG_ERR("Failed to set %s TLS_HOSTNAME "
					"option (%d)", family_str, -errno);
				ret = -errno;
			}
		}
	} else {
		*sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	}

	if (*sock < 0) {
		LOG_ERR("Failed to create %s HTTP socket (%d)", family_str,
			-errno);
	}

	return ret;
}

static int connect_socket(sa_family_t family, const char *server, int port,
			  int *sock, struct sockaddr *addr, socklen_t addr_len)
{
	int ret;

	ret = setup_socket(family, server, port, sock, addr, addr_len);
	if (ret < 0 || *sock < 0) {
		return -1;
	}

	ret = connect(*sock, addr, addr_len);
	if (ret < 0) {
		LOG_ERR("Cannot connect to %s remote (%d)",
			family == AF_INET ? "IPv4" : "IPv6",
			-errno);
		ret = -errno;
	}

	return ret;
}

static bool start_http_client(void)
{
	int ret = -1;
	struct addrinfo *addr;
	struct addrinfo hints;
	int resolve_attempts = 10;
	LOG_INF("start_http_client");

	if (IS_ENABLED(CONFIG_NET_SOCKETS_SOCKOPT_TLS)) {
		ret = tls_credential_add(CA_CERTIFICATE_TAG,
					 TLS_CREDENTIAL_CA_CERTIFICATE,
					 ca_certificate,
					 sizeof(ca_certificate));
		if (ret < 0) {
			LOG_ERR("Failed to register public certificate: %d",
				ret);
			return ret;
		}
	}

	LOG_INF("start_http_client %s:%s",
			CONFIG_AKNANO_SERVER, CONFIG_AKNANO_SERVER_PORT);
	while (resolve_attempts--) {
		ret = getaddrinfo(CONFIG_AKNANO_SERVER, CONFIG_AKNANO_SERVER_PORT,
				  &hints, &addr);
		if (ret == 0) {
			break;
		}

		k_sleep(K_MSEC(1));
	}

	if (ret != 0) {
		LOG_ERR("Could not resolve dns");
		return false;
	}

	connect_socket(addr->ai_family, CONFIG_AKNANO_SERVER,
			CONFIG_AKNANO_SERVER_PORT, &hb_context.sock,
			addr, addr->ai_addrlen);

	ret = connect(hb_context.sock, addr->ai_addr, addr->ai_addrlen);
	if (ret < 0) {
		LOG_ERR("Failed to connect to Server");
		goto err_sock;
	}

	freeaddrinfo(addr);
	return true;

err_sock:
	close(hb_context.sock);
err:
	freeaddrinfo(addr);
	return false;
}

static void cleanup_connection(void)
{
	if (close(hb_context.sock) < 0) {
		LOG_ERR("Could not close the socket");
	}
}

static int aknano_time2sec(const char *s)
{
	int sec;

	/* Time: HH:MM:SS */
	sec = strtol(s, NULL, 10) * (60 * 60);
	sec += strtol(s + 3, NULL, 10) * 60;
	sec += strtol(s + 6, NULL, 10);

	if (sec < 0) {
		return -1;
	} else {
		return sec;
	}
}

/*
 * Update sleep interval, based on results from hawkbit base polling
 * resource
 */
static void aknano_update_sleep(struct aknano_ctl_res *aknano_res)
{
	uint32_t sleep_time;
	const char *sleep = aknano_res->config.polling.sleep;

	if (strlen(sleep) != AKNANO_SLEEP_LENGTH) {
		LOG_ERR("Invalid poll sleep: %s", sleep);
	} else {
		sleep_time = aknano_time2sec(sleep);
		if (sleep_time > 0 && poll_sleep !=
		    (MSEC_PER_SEC * sleep_time)) {
			LOG_DBG("New poll sleep %d seconds", sleep_time);
			poll_sleep = sleep_time * MSEC_PER_SEC;
		}
	}
}

static void aknano_dump_base(struct aknano_ctl_res *r)
{
	LOG_DBG("config.polling.sleep=%s",
		log_strdup(r->config.polling.sleep));
	LOG_DBG("_links.deploymentBase.href=%s",
		log_strdup(r->_links.deploymentBase.href));
	LOG_DBG("_links.configData.href=%s",
		log_strdup(r->_links.configData.href));
	LOG_DBG("_links.cancelAction.href=%s",
		log_strdup(r->_links.cancelAction.href));
}

static int aknano_handle_img_confirmed(void)
{
	bool image_ok;
	int ret;

	image_ok = boot_is_img_confirmed();
	LOG_INF("Image is %s confirmed OK", image_ok ? "" : " not");
	if (!image_ok) {
		ret = boot_write_img_confirmed();
		if (ret < 0) {
			LOG_ERR("Couldn't confirm this image: %d", ret);
			return ret;
		}

		LOG_DBG("Marked image as OK");
		ret = boot_erase_img_bank(FLASH_AREA_ID(image_1));
		if (ret) {
			LOG_ERR("Failed to erase second slot");
			return ret;
		}
	}
	return 0;
}

/* Log the semantic version number of the current image. */
static void log_img_ver(int flash_area_id, uint32_t *build_num)
{
	struct mcuboot_img_header header;
	struct mcuboot_img_sem_ver *ver;
	int ret;

	
	ret = boot_read_bank_header(flash_area_id,
				    &header, sizeof(header));
	if (ret) {
		LOG_ERR("can't read header: %d", ret);
		return;
	} else if (header.mcuboot_version != 1) {
		LOG_ERR("unsupported MCUboot version %u",
			header.mcuboot_version);
		return;
	}

	ver = &header.h.v1.sem_ver;
	LOG_INF("image version %u.%u.%u build #%u",
		ver->major, ver->minor, ver->revision, ver->build_num);

	if (build_num != NULL) {
		*build_num = ver->build_num;
	}
}

int aknano_init(void)
{
	int rc;

	rc = aknano_handle_img_confirmed();
	if (rc) {
		LOG_ERR("Error handling img confirmation");
		return rc;
	}

	LOG_INF("Init success");

	return 0;
}

static int enum_for_http_req_string(char *userdata)
{
	int i = 0;
	char *name = aknano_http_request[i].http_req_str;

	while (name) {
		if (strcmp(name, userdata) == 0) {
			return aknano_http_request[i].n;
		}

		name = aknano_http_request[++i].http_req_str;
	}

	return 0;
}

static int get_http_data_and_length(struct http_response *rsp, 
                        uint8_t **body_data, size_t *body_len, 
						size_t *http_content_size, size_t downloaded_size) 
{
	size_t header_size = 0;

	*body_data = rsp->recv_buf;
	*body_len = rsp->data_len;

	if (*http_content_size == 0) {
		if (rsp->body_found == 0) {
			LOG_ERR("Callback called w/o HTTP header found!");
			return -1;
		}

		/*
		 * WARNING: As of Zephyr, 2.6.0, the bellow code is not enough to 
		 * identify the header size, because rsp->body_start may not be set
		 */
		if (rsp->body_start != NULL && rsp->recv_buf != NULL) {
			header_size = rsp->body_start - rsp->recv_buf;
			LOG_INF("Setting header_size=%u", header_size);
			*body_data = rsp->body_start;
		} else {
			if (rsp->content_length >= 100000)
				header_size	= 258;
			else
				header_size	= 256;
			LOG_WRN("Forcing header_size=%u", header_size);
			LOG_INF("%s", *body_data);
		}

		*body_len -= header_size;
		*http_content_size = rsp->content_length;

		LOG_INF("FIRST: body_len=%u, header=%d http_content_size=%u", 
			*body_len, (rsp->body_start - rsp->recv_buf), *http_content_size);
	}

	LOG_DBG("down_size=%u rsp->body_start=%p rsp->recv_buf=%p *body_len=%u", 
	   downloaded_size, rsp->body_start, rsp->recv_buf, *body_len); 

	return 0;
}


static bool target_has_a_relevant_tag(struct aknano_target_parsed *target)
{
	uint8_t i;

	for (i=0; i<target->custom.tags_len; i++) {
		if (!strncmp(CONFIG_AKNANO_TAG, 
			         target->custom.tags[i], AKNANO_MAX_TAG_LENGTH))
			return true;
	}

	return false;
}

static bool target_is_higher(struct aknano_target_parsed *target, 
                             struct aknano_target *selected_target)
{
	int32_t version = strtol(target->custom.version, NULL, 10);
	LOG_INF("target_is_higher? %d > %d?", version, selected_target->version);
	return version > selected_target->version;
}

static void update_selected_target(struct aknano_target_parsed *target, 
                             struct aknano_target *selected_target)
{
	int32_t version = strtol(target->custom.version, NULL, 10);
	selected_target->version = version;
	strncpy(selected_target->updatedAt, target->custom.updatedAt, 
										AKNANO_MAX_UPDATE_AT_LENGTH);
	strncpy(selected_target->uri, target->custom.uri, AKNANO_MAX_URI_LENGTH);
}

static void update_selected_target_if_necessary(
	                         struct aknano_target_parsed *target, 
                             struct aknano_target *selected_target)
{
	if (!target_has_a_relevant_tag(target))
		return;
	
	if (target_is_higher(target, selected_target)) {
		update_selected_target(target, selected_target);
		LOG_INF("Updated higher version to %d uri='%s' updatedAt='%s'", 
						selected_target->version, selected_target->uri,
						selected_target->updatedAt);
	}
}

static int handle_json_data(uint8_t *data, size_t len)
{
	int ret;
	struct aknano_target_parsed target;

	data[len] = '\0';
	LOG_INF("Received JSON: len=%d", len);
	/* LOG_INF("'%s'\n", data); */

	memset(&target, 0, sizeof(target));
	target.length = 99;
	ret = json_obj_parse(data,
					len, json_aknano_target_descr,
					ARRAY_SIZE(json_aknano_target_descr),
					&target);

	if (ret < 0) {
		LOG_ERR("JSON parse error");
		hb_context.code_status =
			AKNANO_METADATA_ERROR;
	}

	update_selected_target_if_necessary(&target, 
		&hb_context.aknano_json_data.selected_target);

	LOG_INF("Parsed len=%d version=%s uri=%s", 
		target.length, target.custom.version, target.custom.uri);
	return 0;
}

static void aknano_handle_manifest_data(uint8_t *dst, size_t *offset, 
                                  uint8_t *src, size_t len)
{
	static int bracket_level; /* TODO: move to context structure */
	bool is_relevant_data;
	uint8_t *p = src;

	/* 
	 * Based on current format, counting brackets ({ and }) is enough 
	 * to determine when a "target" section starts and ends. 
	 * We should process all data that is inside the 4th bracket level.
	 * And a target section is known to end every time we go back to the
	 * 3rd bracket level.
	 */
	is_relevant_data = bracket_level >= 4;

	while (p < src + len) {
		switch (*p) {
		case '{': 
			bracket_level++;
			is_relevant_data = bracket_level >= 4;
			break;
		case '}':
			bracket_level--;
			break;
		}
		if (is_relevant_data) {
			*(dst + *offset) = *p;
			(*offset)++;

			if (bracket_level == 3) {
				*(dst + *offset) = '\0';
				/* A complete target section was received. Process it */
				handle_json_data(dst, *offset);
				is_relevant_data = false;
				*offset = 0;
			}
		}
		p++;
	}
}

static void response_cb(struct http_response *rsp,
			enum http_final_call final_data,
			void *userdata)
{
	static size_t body_len;
	int ret, type, downloaded;
	uint8_t *body_data = NULL;

	type = enum_for_http_req_string(userdata);
	switch (type) {
	case AKNANO_PROBE:
		if (rsp->http_status_code != 200) {
			LOG_WRN("Got HTTP error: %d (%s)", rsp->http_status_code, rsp->http_status);
			ret = -1;
		} else {
			ret = get_http_data_and_length(rsp, &body_data, &body_len,
				&hb_context.dl.http_content_size, hb_context.dl.downloaded_size);
		}
		if (ret < 0) {
			hb_context.code_status = AKNANO_METADATA_ERROR;
			break; // goto error;
		}
		aknano_handle_manifest_data(hb_context.response_data, 
		       &hb_context.aknano_json_data.offset,
			   body_data, body_len);
		hb_context.dl.downloaded_size += body_len;

		if (final_data == HTTP_DATA_FINAL) {
			if (hb_context.dl.http_content_size 
				!= hb_context.dl.downloaded_size) {
				LOG_ERR("HTTP response len mismatch expected (%u) != got (%u)", 
				hb_context.dl.http_content_size, hb_context.dl.downloaded_size);
				/* hb_context.code_status =	AKNANO_METADATA_ERROR; */
			}

			LOG_INF("FINAL: higher version: %d uri='%s' updatedAt='%s'", 
				hb_context.aknano_json_data.selected_target.version, 
				hb_context.aknano_json_data.selected_target.uri, 
				hb_context.aknano_json_data.selected_target.updatedAt); 

			hb_context.dl.downloaded_size = 0;
		}

		break;

	case AKNANO_CLOSE:
	case AKNANO_REPORT:
	case AKNANO_CONFIG_DEVICE:
		if (strcmp(rsp->http_status, "OK") < 0) {
			LOG_ERR("Failed to cancel the update");
		}

		break;

	case AKNANO_PROBE_DEPLOYMENT_BASE:
		LOG_INF("AKNANO_PROBE_DEPLOYMENT_BASE: not implemented");
		break;

	case AKNANO_DOWNLOAD:
		ret = get_http_data_and_length(rsp, &body_data, &body_len, 
		    &hb_context.dl.http_content_size, hb_context.dl.downloaded_size);

		if (ret < 0) {
			hb_context.code_status = AKNANO_METADATA_ERROR;
			break;
		}

		if (body_data != NULL) {
			LOG_INF("Writting %d bytes to flash", body_len);
			if (hb_context.dl.downloaded_size < 10000)
				LOG_HEXDUMP_INF(body_data, body_len, "DATA: ");
#ifdef AK_NANO_DRY_RUN
			ret = 0;
#else
			ret = flash_img_buffered_write(&hb_context.flash_ctx,
				body_data, body_len,
				final_data == HTTP_DATA_FINAL);
#endif
			if (ret < 0) {
				LOG_ERR("flash write error");
				hb_context.code_status = AKNANO_DOWNLOAD_ERROR;
			}
		}

		hb_context.dl.downloaded_size += body_len;
		downloaded = hb_context.dl.downloaded_size * 100 /
			     hb_context.dl.http_content_size;

		if (downloaded > hb_context.dl.download_progress) {
			hb_context.dl.download_progress = downloaded;
			LOG_INF("Download percentage: %d%% ",
				hb_context.dl.download_progress);
		}

		if (final_data == HTTP_DATA_FINAL) {
			k_sem_give(&hb_context.semaphore);
		}

		break;
	}
}

static bool send_request(enum http_method method,
			 enum aknano_http_request type,
			 enum aknano_status_fini finished,
			 enum aknano_status_exec execution)
{
	int ret = 0;
	char device_id[DEVICE_ID_HEX_MAX_SIZE] = { 0 };

	if (!aknano_get_device_identity(device_id, DEVICE_ID_HEX_MAX_SIZE)) {
		hb_context.code_status = AKNANO_METADATA_ERROR;
	}

	memset(&hb_context.http_req, 0, sizeof(hb_context.http_req));
	memset(&hb_context.recv_buf_tcp, 0, sizeof(hb_context.recv_buf_tcp));
	hb_context.http_req.url = hb_context.url_buffer;
	LOG_INF("hb_context.url_buffer=%s", hb_context.url_buffer);
	hb_context.http_req.method = method;
	hb_context.http_req.host = CONFIG_AKNANO_SERVER;
	hb_context.http_req.port = CONFIG_AKNANO_SERVER_PORT;
	hb_context.http_req.protocol = "HTTP/1.1";
	hb_context.http_req.response = response_cb;
	hb_context.http_req.recv_buf = hb_context.recv_buf_tcp;
	hb_context.http_req.recv_buf_len = sizeof(hb_context.recv_buf_tcp);

	switch (type) {
	case AKNANO_PROBE:
		memset(&hb_context.aknano_json_data, 0, 
			sizeof(hb_context.aknano_json_data));
		ret = http_client_req(hb_context.sock, &hb_context.http_req,
				      AKNANO_RECV_TIMEOUT, "AKNANO_PROBE");
		if (ret < 0) {
			LOG_ERR("Unable to send http request");
			return false;
		}

		break;

	case AKNANO_CONFIG_DEVICE:
		LOG_INF("AKNANO_CONFIG_DEVICE: not implemented");
		break;

	case AKNANO_CLOSE:
		LOG_INF("AKNANO_CLOSE: not implemented");
		break;

	case AKNANO_PROBE_DEPLOYMENT_BASE:
		hb_context.http_req.content_type_value = NULL;
		ret = http_client_req(hb_context.sock, &hb_context.http_req,
				      AKNANO_RECV_TIMEOUT,
				      "AKNANO_PROBE_DEPLOYMENT_BASE");
		if (ret < 0) {
			LOG_ERR("Unable to send http request");
			return false;
		}

		break;

	case AKNANO_REPORT:
		LOG_INF("AKNANO_REPORT: not implemented");
		break;

	case AKNANO_DOWNLOAD:
		ret = http_client_req(hb_context.sock, &hb_context.http_req,
				      AKNANO_RECV_TIMEOUT, "AKNANO_DOWNLOAD");
		if (ret < 0) {
			LOG_ERR("Unable to send image download request");
			return false;
		}

		break;
	}

	return true;
}

enum aknano_response aknano_probe(void)
{
	int ret;
	uint32_t current_build = 0;
	char device_id[DEVICE_ID_HEX_MAX_SIZE] = { 0 };
	char firmware_version[BOOT_IMG_VER_STRLEN_MAX] = { 0 };

	LOG_INF("aknano_probe");

	memset(&hb_context, 0, sizeof(hb_context));
	hb_context.response_data = malloc(RESPONSE_BUFFER_SIZE);
	memset(hb_context.response_data, 0, RESPONSE_BUFFER_SIZE);
	k_sem_init(&hb_context.semaphore, 0, 1);

	if (0 && !boot_is_img_confirmed()) {
		LOG_ERR("The current image is not confirmed");
		hb_context.code_status = AKNANO_UNCONFIRMED_IMAGE;
		goto error;
	}

	if (!aknano_get_firmware_version(firmware_version,
					  BOOT_IMG_VER_STRLEN_MAX)) {
		hb_context.code_status = AKNANO_METADATA_ERROR;
		goto error;
	}

	if (!aknano_get_device_identity(device_id, DEVICE_ID_HEX_MAX_SIZE)) {
		hb_context.code_status = AKNANO_METADATA_ERROR;
		goto error;
	}

	if (!start_http_client()) {
		hb_context.code_status = AKNANO_NETWORKING_ERROR;
		goto error;
	}

	/*
	 * Query the aknano base polling resource.
	 */
	LOG_INF("Polling target data from Aktualizr-nano");

	memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
	hb_context.dl.http_content_size = 0;
	hb_context.url_buffer_size = URL_BUFFER_SIZE;
	snprintk(hb_context.url_buffer, hb_context.url_buffer_size, "%s/%s-%s",
		 AKNANO_JSON_URL, CONFIG_BOARD, device_id);
	memset(&aknano_results.base, 0, sizeof(aknano_results.base));

	if (!send_request(HTTP_GET, AKNANO_PROBE, AKNANO_STATUS_FINISHED_NONE,
			  AKNANO_STATUS_EXEC_NONE)) {
		LOG_ERR("Send request failed");
		hb_context.code_status = AKNANO_NETWORKING_ERROR;
		goto cleanup;
	}

	if (hb_context.code_status == AKNANO_METADATA_ERROR) {
		goto error;
	}

	if (aknano_results.base.config.polling.sleep) {
		/* Update the sleep time. */
		aknano_update_sleep(&aknano_results.base);
	}

	aknano_dump_base(&aknano_results.base);

	if (hb_context.aknano_json_data.selected_target.version <= 0) {
	 	hb_context.code_status = AKNANO_NO_UPDATE;
	 	goto cleanup;
	}

	LOG_INF("Reading version for image_0");
	log_img_ver(FLASH_AREA_ID(image_0), &current_build);
	LOG_INF("Current installed version: %u latest available: %u", 
		current_build, hb_context.aknano_json_data.selected_target.version);
	if (hb_context.aknano_json_data.selected_target.version <= current_build) {
		LOG_INF("Keeping current version, no update");
	 	hb_context.code_status = AKNANO_NO_UPDATE;
	 	goto cleanup;
	}

	memset(hb_context.url_buffer, 0, sizeof(hb_context.url_buffer));
	hb_context.dl.http_content_size = 0;
	hb_context.url_buffer_size = URL_BUFFER_SIZE;

	snprintk(hb_context.url_buffer, hb_context.url_buffer_size,
	 	"%s", hb_context.aknano_json_data.selected_target.uri);
	memset(&aknano_results.dep, 0, sizeof(aknano_results.dep));
	memset(hb_context.response_data, 0, RESPONSE_BUFFER_SIZE);


#ifndef AK_NANO_DRY_RUN
	LOG_INF("Erasing image_1");
	ret = boot_erase_img_bank(FLASH_AREA_ID(image_1));
	if (ret) {
		LOG_ERR("Failed to erase second slot");
	}
#endif

	LOG_INF("Starting image download for uri=%s", hb_context.url_buffer);
	flash_img_init(&hb_context.flash_ctx);
	if (!send_request(HTTP_GET, AKNANO_DOWNLOAD,
			  AKNANO_STATUS_FINISHED_NONE,
			  AKNANO_STATUS_EXEC_NONE)) {
		LOG_ERR("Send request failed");
		hb_context.code_status = AKNANO_NETWORKING_ERROR;
		goto cleanup;
	}

	if (hb_context.code_status == AKNANO_DOWNLOAD_ERROR) {
		goto cleanup;
	}
	LOG_INF("Requesting MCUBoot image swap");

#ifndef AK_NANO_DRY_RUN
	if (boot_request_upgrade(BOOT_UPGRADE_PERMANENT)) {
		LOG_ERR("Download failed");
		hb_context.code_status = AKNANO_DOWNLOAD_ERROR;
	} else {
		hb_context.code_status = AKNANO_UPDATE_INSTALLED;
		/* aknano_device_acid_update(hb_context.json_action_id); */
		LOG_INF("Image written");
	}
#endif

	hb_context.dl.http_content_size = 0;

cleanup:
	cleanup_connection();

error:
	free(hb_context.response_data);
	return hb_context.code_status;
}

static void autohandler(struct k_work *work)
{
	switch (aknano_probe()) {
	case AKNANO_UNCONFIRMED_IMAGE:
		LOG_ERR("Image is unconfirmed");
		LOG_ERR("Rebooting to previous confirmed image.");
		sys_reboot(SYS_REBOOT_WARM);
		break;

	case AKNANO_NO_UPDATE:
		LOG_INF("No update found");
		break;

	case AKNANO_CANCEL_UPDATE:
		LOG_INF("Hawkbit update Cancelled from server");
		break;

	case AKNANO_OK:
		LOG_INF("Image is already updated");
		break;

	case AKNANO_UPDATE_INSTALLED:
		LOG_INF("Update Installed. Please Reboot");

#ifndef AK_NANO_DRY_RUN
		LOG_INF("Rebooting");
		sys_reboot(SYS_REBOOT_WARM);
#endif
		break;

	case AKNANO_DOWNLOAD_ERROR:
		LOG_INF("Update Failed");
		break;

	case AKNANO_NETWORKING_ERROR:
		LOG_INF("Network Error");
		break;

	case AKNANO_METADATA_ERROR:
		LOG_INF("Metadata error");
		break;
	}

	k_work_reschedule(&aknano_work_handle, K_MSEC(poll_sleep));
}

void aknano_autohandler(void)
{
	k_work_init_delayable(&aknano_work_handle, autohandler);
	k_work_reschedule(&aknano_work_handle, K_NO_WAIT);
	LOG_INF("Scheduled work handle");
}
