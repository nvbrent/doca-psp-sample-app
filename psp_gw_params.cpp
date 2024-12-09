/*
 * Copyright (c) 2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <ctype.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fstream>
#include <sstream>
#include <json-c/json.h>
#include <functional>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>

#include <psp_gw_config.h>
#include <psp_gw_params.h>
#include <psp_gw_utils.h>

DOCA_LOG_REGISTER(PSP_Gateway_Params);

/* JSON parsing callback */
using psp_parse_json_object_cb = std::function<doca_error_t(json_object *, psp_gw_app_config *, void *)>;

/* JSON handler struct */
struct psp_json_field_handler {
	const std::string key;		    /* JSON key */
	psp_parse_json_object_cb parser_cb; /* JSON parser callback */
	bool required;			    /* Is the key mandatory */
	bool found;			    /* Was the key found - used internally */
	/* Constructor that sets the found flag to false */
	psp_json_field_handler(const std::string &key, psp_parse_json_object_cb parser_cb, bool required)
		: key(key),
		  parser_cb(parser_cb),
		  required(required),
		  found(false)
	{
	}
};

/* JSON handler vector */
using psp_json_field_handlers = std::vector<psp_json_field_handler>;


/**
 * @brief Configures the DPDK eal_init Core mask parameter
 *
 * @param [in]: the core mask string
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_core_mask_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;

	app_config->core_mask = (char *)param;

	DOCA_LOG_INFO("RTE EAL core-mask: %s", app_config->core_mask.c_str());
	return DOCA_SUCCESS;
}

/**
 * @brief Configures the dst-mac to apply on decap
 *
 * @param [in]: the dst mac addr
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_decap_dmac_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	char *mac_addr = (char *)param;

	if (!is_empty_mac_addr(app_config->dcap_dmac)) {
		DOCA_LOG_ERR("Cannot specify both --decap-dmac and --vf-name");
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (rte_ether_unformat_addr(mac_addr, &app_config->dcap_dmac) != 0) {
		DOCA_LOG_ERR("Malformed mac addr: %s", mac_addr);
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_INFO("Decap dmac: %s", mac_addr);
	return DOCA_SUCCESS;
}

/**
 * @brief Configures the next-hop dst-mac to apply on encap
 *
 * @param [in]: the dst mac addr
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_nexthop_dmac_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	char *mac_addr = (char *)param;

	if (rte_ether_unformat_addr(mac_addr, &app_config->nexthop_dmac) != 0) {
		DOCA_LOG_ERR("Malformed mac addr: %s", mac_addr);
		return DOCA_ERROR_INVALID_VALUE;
	}

	app_config->nexthop_enable = true;

	DOCA_LOG_INFO("Next-Hop dmac: %s", mac_addr);
	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the application should include the VC in the PSP tunnel header
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_vc_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	bool *bool_param = (bool *)param;
	app_config->net_config.vc_enabled = *bool_param;
	DOCA_LOG_INFO("PSP VCs %s", *bool_param ? "Enabled" : "Disabled");
	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the application should skip ACL checks on ingress
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_ingress_acl_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	bool *bool_param = (bool *)param;
	app_config->disable_ingress_acl = *bool_param;
	DOCA_LOG_INFO("Ingress ACLs %s", *bool_param ? "Disabled" : "Enabled");
	return DOCA_SUCCESS;
}

/**
 * @brief Configures the sampling rate of packets
 *
 * @param [in]: The log2 rate; see log2_sample_rate
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_sample_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	int32_t *int_param = (int32_t *)param;
	app_config->log2_sample_rate = (uint16_t)*int_param;
	DOCA_LOG_INFO("The log2_sample_rate is set to %d", app_config->log2_sample_rate);
	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the application should create all PSP tunnels at startup
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_static_tunnels_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	app_config->create_tunnels_at_startup = (bool *)param;

	DOCA_LOG_INFO("Create PSP tunnels at startup: %s",
		      app_config->create_tunnels_at_startup ? "Enabled" : "Disabled");

	return DOCA_SUCCESS;
}

/**
 * @brief Configures the max number of tunnels to be supported.
 *
 * @param [in]: A pointer to the parameter
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_max_tunnels_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	int *int_param = (int *)param;
	if (*int_param < 1) {
		DOCA_LOG_ERR("The max-tunnels cannot be less than one");
		return DOCA_ERROR_INVALID_VALUE;
	}

	app_config->max_tunnels = *int_param;
	DOCA_LOG_INFO("Configured max-tunnels = %d", app_config->max_tunnels);

	return DOCA_SUCCESS;
}

/**
 * @brief Configures the PSP crypt-offset, the number of words in
 * the packet header transmitted as cleartext.
 *
 * @param [in]: A pointer to the parameter
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_psp_crypt_offset_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	int *int_param = (int *)param;
	if (*int_param < 0 || *int_param >= 0x3f) {
		DOCA_LOG_ERR("PSP crypt-offset must be a 6-bit integer");
		return DOCA_ERROR_INVALID_VALUE;
	}

	app_config->net_config.crypt_offset = *int_param;
	DOCA_LOG_INFO("Configured PSP crypt_offset = %d", app_config->net_config.crypt_offset);

	return DOCA_SUCCESS;
}

/**
 * @brief Configures the PSP version to use for outgoing connections.
 *
 * @param [in]: A pointer to the parameter
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_psp_version_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	int *int_param = (int *)param;
	if (!SUPPORTED_PSP_VERSIONS.count(*int_param)) {
		DOCA_LOG_ERR("Unsupported PSP version: %d", *int_param);
		return DOCA_ERROR_INVALID_VALUE;
	}

	app_config->net_config.default_psp_proto_ver = *int_param;
	DOCA_LOG_INFO("Configured PSP version = %d", app_config->net_config.default_psp_proto_ver);

	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the application should log all encryption keys
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_debug_keys_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	bool *bool_param = (bool *)param;
	app_config->debug_keys = *bool_param;
	if (*bool_param) {
		DOCA_LOG_INFO("NOTE: debug_keys is enabled; crypto keys will be written to logs.");
	}
	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the name of the netdev used as the unsecured port.
 * From this, derive the MAC and IP addresses.
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_vf_name_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	std::string vf_iface_name = (const char *)param;

	if (!is_empty_mac_addr(app_config->dcap_dmac)) {
		DOCA_LOG_ERR("Cannot specify both --vf-name and --decap-dmac");
		return DOCA_ERROR_INVALID_VALUE;
	}

	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		DOCA_LOG_ERR("Failed to open socket");
		return DOCA_ERROR_IO_FAILED;
	}

	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, vf_iface_name.c_str(), IFNAMSIZ - 1);

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		DOCA_LOG_ERR("Failed ioctl(sockfd, SIOCGIFADDR, &ifr)");
		close(sockfd);
		return DOCA_ERROR_IO_FAILED;
	}

	rte_be32_t vf_ip_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
	app_config->local_vf_addr = ipv4_to_string(vf_ip_addr);

	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
		DOCA_LOG_ERR("Failed ioctl(sockfd, SIOCGIFHWADDR, &ifr)");
		close(sockfd);
		return DOCA_ERROR_IO_FAILED;
	}

	app_config->dcap_dmac = *(rte_ether_addr *)ifr.ifr_hwaddr.sa_data;
	close(sockfd);

	DOCA_LOG_INFO("For VF device %s, detected IP addr %s, mac addr %s",
		      vf_iface_name.c_str(),
		      app_config->local_vf_addr.c_str(),
		      mac_to_string(app_config->dcap_dmac).c_str());

	return DOCA_SUCCESS;
}

/**
 * @brief Indicates wherever statistics should be printed
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_stats_print_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	bool *bool_param = (bool *)param;
	app_config->print_stats = *bool_param;
	DOCA_LOG_INFO("Stats %s", *bool_param ? "Enabled" : "Disabled");
	return DOCA_SUCCESS;
}

/**
 * @brief returns supported perf types as a string
 *
 * @supported_types [out]: string to store supported types
 */
static void get_supported_perf_types(std::string &supported_types)
{
	bool first = true;
	for (const auto &type : PSP_PERF_MAP) {
		supported_types += (first ? "" : ", ") + type.first;
		first = false;
	}
}

/**
 * @brief indicates what performance printing should be enabled
 *
 * @param [in]: A pointer to a string types: key-gen, insertion
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_perf_print_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;

	std::string perf_types = (const char *)param;
	std::istringstream perf_types_stream(perf_types);
	for (std::string perf_type; std::getline(perf_types_stream, perf_type, ',');) {
		if (PSP_PERF_MAP.count(perf_type) == 0) {
			std::string supported_types;
			get_supported_perf_types(supported_types);
			DOCA_LOG_ERR("Unsupported perf type: %s, supported types: %s",
				     perf_type.c_str(),
				     supported_types.c_str());
			return DOCA_ERROR_INVALID_VALUE;
		}
		app_config->print_perf_flags |= PSP_PERF_MAP.at(perf_type);
	}
	DOCA_LOG_INFO("Enabled perf print for %s", perf_types.c_str());
	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the application should log all packets received to RSS
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_show_rss_rx_packets_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	bool *bool_param = (bool *)param;
	app_config->show_rss_rx_packets = *bool_param;
	if (*bool_param) {
		DOCA_LOG_INFO(
			"NOTE: show_rss_rx_packets is enabled; rx packets received to RSS will be written to logs.");
	}
	return DOCA_SUCCESS;
}

/**
 * @brief Handle outer IP type param
 *
 * @param [in]: A pointer to a string flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_outer_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	std::string outer_type = (const char *)param;

	if (outer_type == "ipv4") {
		app_config->outer = DOCA_FLOW_L3_TYPE_IP4;
	} else if (outer_type == "ipv6") {
		app_config->outer = DOCA_FLOW_L3_TYPE_IP6;
	} else {
		DOCA_LOG_ERR("Unsupported outer type: %s, supported types: ipv4, ipv6", outer_type.c_str());
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_INFO("Outer type: %s", outer_type.c_str());
	return DOCA_SUCCESS;
}

/**
 * @brief Utility function to create a single argp parameter
 *
 * @short_name [in]: The single-letter command-line flag
 * @long_name [in]: The spelled-out command-line flag
 * @description [in]: Describes the option
 * @cb [in]: Called when the option is parsed
 * @arg_type [in]: How the option string should be parsed
 * @required [in]: Whether the program should terminate if the option is omitted
 * @accept_multiple [in]: Whether the program should accept multiple instances of the option
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t psp_gw_register_single_param(const char *short_name,
						 const char *long_name,
						 const char *description,
						 doca_argp_param_cb_t cb,
						 enum doca_argp_type arg_type,
						 bool required,
						 bool accept_multiple)
{
	struct doca_argp_param *param = NULL;
	doca_error_t result = doca_argp_param_create(&param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	if (short_name)
		doca_argp_param_set_short_name(param, short_name);
	if (long_name)
		doca_argp_param_set_long_name(param, long_name);
	if (description)
		doca_argp_param_set_description(param, description);
	if (cb)
		doca_argp_param_set_callback(param, cb);
	if (required)
		doca_argp_param_set_mandatory(param);
	if (accept_multiple)
		doca_argp_param_set_multiplicity(param);

	doca_argp_param_set_type(param, arg_type);
	result = doca_argp_register_param(param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param %s: %s",
			     long_name ? long_name : short_name,
			     doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/**
 * @brief Configures the JSON config file path
 *
 * @param [in]: A pointer to the JSON file path
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_config_file_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	std::string json_path = (char *)param;

	if (json_path.length() >= MAX_FILE_NAME) {
		DOCA_LOG_ERR("JSON file name is too long - MAX=%d", MAX_FILE_NAME - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}
	if (access(json_path.c_str(), F_OK) == -1) {
		DOCA_LOG_ERR("JSON file was not found %s", json_path.c_str());
		return DOCA_ERROR_NOT_FOUND;
	}
	app_config->json_path = json_path;
	DOCA_LOG_INFO("Using JSON file: %s", app_config->json_path.c_str());

	return DOCA_SUCCESS;
}

/* --------------------- JSON Parsing --------------------- */

/**
 * @brief Verifies and extract the string from json object
 *
 * @json_obj [in]: json object
 * @value [out]: string value to extract
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t json_object_ver_get_string(json_object *json_obj, std::string &value)
{
	if (!json_object_is_type(json_obj, json_type_string)) {
		DOCA_LOG_ERR("Invalid JSON object type: %d, expected string", json_object_get_type(json_obj));
		return DOCA_ERROR_INVALID_VALUE;
	}
	value = json_object_get_string(json_obj);
	return DOCA_SUCCESS;
}

/**
 * @brief Verifies and extract the array length from json object
 *
 * @json_obj [in]: json object
 * @length [out]: array length to extract
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 *
 * @NOTE: Does not return the array itself, only the length.
 */
static doca_error_t json_object_ver_array_length(json_object *json_obj, int &length)
{
	if (!json_object_is_type(json_obj, json_type_array)) {
		DOCA_LOG_ERR("Invalid JSON object type: %d, expected array", json_object_get_type(json_obj));
		return DOCA_ERROR_INVALID_VALUE;
	}
	length = json_object_array_length(json_obj);
	return DOCA_SUCCESS;
}

/**
 * @brief Handles a JSON object with all his keys
 *
 * @handlers [in]: JSON handlers (expected keys and handlers)
 * @json_obj [in]: JSON object
 * @app_config [in/out]: Application config
 * @data [in/out]: Custom data to pass to the handler
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_json_level_fields(psp_json_field_handlers &handlers,
					     json_object *json_obj,
					     psp_gw_app_config *app_config,
					     void *data = nullptr)
{
	doca_error_t result = DOCA_SUCCESS;

	// Note that json parser will erase randomly any duplicated key, so this is not checked. it is up to user to
	// ensure
	json_object_object_foreach(json_obj, key, val)
	{
		bool found = false;
		for (auto &handler : handlers) {
			if (strcmp(key, handler.key.c_str()) == 0) {
				result = handler.parser_cb(val, app_config, data);
				if (result != DOCA_SUCCESS) {
					return result;
				}
				found = true;
				handler.found = true;
				break;
			}
		}
		if (!found) {
			DOCA_LOG_ERR("Invalid key in JSON file: %s", key);
			return DOCA_ERROR_INVALID_VALUE;
		}
	}

	/* verify all required keys were found */
	for (auto &handler : handlers) {
		if (handler.required && !handler.found) {
			DOCA_LOG_ERR("Missing required key in JSON file: %s", handler.key.c_str());
			return DOCA_ERROR_INVALID_VALUE;
		}
	}

	return DOCA_SUCCESS;
}

/**
 * @brief Parse the local gRPC address
 *
 * @json_obj_local_addr [in]: JSON object
 * @app_config [in/out]: Application config
 * @data [in/out]: Custom data to pass to the handler
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t parse_local_grpc_address(json_object *json_obj_local_addr,
					     psp_gw_app_config *app_config,
					     void *data)
{
	(void)data;
	doca_error_t result = json_object_ver_get_string(json_obj_local_addr, app_config->local_svc_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid local-grpc-address, expected string");
		return result;
	}
	std::string server = app_config->local_svc_addr;

	/* verify legal format: address:port or address*/
	size_t sep = app_config->local_svc_addr.find(':');
	if (sep != 0 && sep != std::string::npos) {
		std::string port = server.substr(sep + 1);
		server = server.substr(0, sep);
		if (port.empty()) {
			DOCA_LOG_ERR("Invalid port in local-grpc-address: %s", server.c_str());
			return DOCA_ERROR_INVALID_VALUE;
		}
		if (port.find_first_not_of("0123456789") != std::string::npos) {
			DOCA_LOG_ERR("Invalid port in local-grpc-address: %s", port.c_str());
			return DOCA_ERROR_INVALID_VALUE;
		}
		int port_num = std::stoi(port);
		if (port_num < 0 || port_num > 65535) {
			DOCA_LOG_ERR("Invalid port in local-grpc-address: %s", port.c_str());
			return DOCA_ERROR_INVALID_VALUE;
		}
	}

	doca_be32_t local_svc_ip;
	if (inet_pton(AF_INET, server.c_str(), &local_svc_ip) != 1) {
		DOCA_LOG_ERR("Invalid local IPv4 addr: %s", server.c_str());
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_DBG("Local gRPC address: %s", app_config->local_svc_addr.c_str());

	return DOCA_SUCCESS;
}

/**
 * @brief Parses the remote gRPC address
 *
 * @json_obj_config [in]: JSON object
 * @app_config [in/out]: Application config
 * @data [in/out]: Custom data to pass to the handler
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t parse_json_config(json_object *json_obj_config, psp_gw_app_config *app_config, void *data)
{
	(void)data;
	psp_json_field_handlers handlers = {
		{"local-grpc-address", parse_local_grpc_address, false},
	};
	doca_error_t result = handle_json_level_fields(handlers, json_obj_config, app_config, nullptr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse JSON config");
		return result;
	}

	return DOCA_SUCCESS;
}

static doca_error_t parse_hostname(json_object *json_obj_remote_addr,
					      psp_gw_app_config *app_config,
					      void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;

	doca_error_t result = json_object_ver_get_string(json_obj_remote_addr, host->hostname);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid hostname, expected string");
		return result;
	}

	return DOCA_SUCCESS;
}

static doca_error_t parse_nexthop(json_object *json_obj_remote_addr,
					      psp_gw_app_config *app_config,
					      void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;

	std::string nexthop_str;
	doca_error_t result = json_object_ver_get_string(json_obj_remote_addr, nexthop_str);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid nexthop, expected string");
		return result;
	}

	int res = rte_ether_unformat_addr(nexthop_str.c_str(), &host->nexthop_mac);
	if (res != 0) {
		DOCA_LOG_ERR("Invalid nexthop mac addr: %s", nexthop_str.c_str());
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

static doca_error_t parse_repr(json_object *json_obj_remote_addr,
					      psp_gw_app_config *app_config,
					      void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;

	doca_error_t result = json_object_ver_get_string(json_obj_remote_addr, host->repr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid pci, expected string");
		return result;
	}

	return DOCA_SUCCESS;
}

static doca_error_t parse_pci(json_object *json_obj_remote_addr,
					      psp_gw_app_config *app_config,
					      void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;

	doca_error_t result = json_object_ver_get_string(json_obj_remote_addr, host->pci);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid pci, expected string");
		return result;
	}

	return DOCA_SUCCESS;
}

static doca_error_t parse_pip(json_object *json_obj_remote_addr,
					      psp_gw_app_config *app_config,
					      void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;

	doca_error_t result = json_object_ver_get_string(json_obj_remote_addr, host->pip);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid pip, expected string");
		return result;
	}

	return DOCA_SUCCESS;
}

/**
 * @brief Parses the remote gRPC address
 *
 * @json_obj_remote_addr [in]: JSON object
 * @app_config [in/out]: Application config
 * @data [in/out]: Custom data to pass to the handler
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t parse_grpc_address(json_object *json_obj_remote_addr,
					      psp_gw_app_config *app_config,
					      void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;

	std::string svcaddr;
	doca_error_t result = json_object_ver_get_string(json_obj_remote_addr, host->svc_ip_str);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid remote-grpc-address, expected string");
		return result;
	}

	if (inet_pton(AF_INET, host->svc_ip_str.c_str(), &host->svc_ip) != 1) {
		DOCA_LOG_ERR("Invalid svc IPv4 addr: %s", host->svc_ip_str.c_str());
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_DBG("gRPC address: %s", host->svc_ip_str.c_str());

	return DOCA_SUCCESS;
}

/**
 * @brief Parses the remote VIPs
 *
 * @json_obj_remote_vips [in]: JSON object
 * @app_config [in/out]: Application config
 * @data [in/out]: Custom data to pass to the handler
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t parse_vips(json_object *json_obj_remote_vips, psp_gw_app_config *app_config, void *data)
{
	(void)app_config;
	struct psp_gw_nic_desc_t *host = (struct psp_gw_nic_desc_t *)data;
	int nb_vips;

	doca_error_t result = json_object_ver_array_length(json_obj_remote_vips, nb_vips);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid remote-vips, expected array");
		return result;
	}
	if (nb_vips == 0) {
		DOCA_LOG_ERR("No remote vips found in JSON file");
		return DOCA_ERROR_INVALID_VALUE;
	}

	for (int i = 0; i < nb_vips; i++) {
		json_object *json_obj_vip = json_object_array_get_idx(json_obj_remote_vips, i);
		std::string vip_str;
		doca_error_t result = json_object_ver_get_string(json_obj_vip, vip_str);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Invalid vip, expected string");
			return result;
		}

		host->vips.push_back(vip_str);
	}

	return DOCA_SUCCESS;
}

/**
 * @brief Parses the peers
 *
 * @json_obj_peers [in]: JSON object
 * @app_config [in/out]: Application config
 * @data [in/out]: Custom data to pass to the handler
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t parse_json_hosts(json_object *json_obj_peers, psp_gw_app_config *app_config, void *data)
{
	(void)data;
	int nb_hosts;
	doca_error_t result = json_object_ver_array_length(json_obj_peers, nb_hosts);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Invalid peers, expected array");
		return result;
	}

	if (nb_hosts == 0) {
		DOCA_LOG_WARN("No peers found in JSON file");
		return DOCA_SUCCESS;
	}

	if ((uint32_t)nb_hosts > PSP_MAX_PEERS) {
		DOCA_LOG_ERR("Too many peers in JSON file: %d, max allowed: %d", nb_hosts, PSP_MAX_PEERS);
		return DOCA_ERROR_INVALID_VALUE;
	}

	for (int i = 0; i < nb_hosts; i++) {
		DOCA_LOG_DBG("Peer %d :", i);
		json_object *json_obj_peer = json_object_array_get_idx(json_obj_peers, i);
		struct psp_gw_nic_desc_t nic = {};

		psp_json_field_handlers handlers = {
			{"hostname", parse_hostname, true},
			{"nexthop", parse_nexthop, true},
			{"grpc-address", parse_grpc_address, true},
			{"pci", parse_pci, true},
			{"repr", parse_repr, true},
			{"pip", parse_pip, true},
			{"vips", parse_vips, true},
		};

		doca_error_t result = handle_json_level_fields(handlers, json_obj_peer, app_config, (void *)&nic);
		if (result != DOCA_SUCCESS) {
			return result;
		}

		// Separate local and remote NICs by hostname
		if (nic.hostname == app_config->hostname) {
			app_config->net_config.local_nics.push_back(nic);
		} else {
			app_config->net_config.remote_nics.push_back(nic);
		}
	}

	return DOCA_SUCCESS;
}

doca_error_t psp_gw_parse_config_file(psp_gw_app_config *app_config)
{
	doca_error_t result;

	std::ifstream in{app_config->json_path};
	if (!in.good()) {
		DOCA_LOG_ERR("Failed to open JSON file");
		return DOCA_ERROR_NOT_FOUND;
	}

	// Read the entire file into a string
	std::string json_content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

	// Close the file
	in.close();

	enum json_tokener_error json_err = json_tokener_success;
	json_object *parsed_json = json_tokener_parse_verbose(json_content.c_str(), &json_err);
	if (parsed_json == nullptr || json_err != json_tokener_success) {
		DOCA_LOG_ERR("Failed to parse JSON file(: %s)", json_tokener_error_desc(json_err));
		return DOCA_ERROR_INVALID_VALUE;
	}

	psp_json_field_handlers handlers = {
		{"config", parse_json_config, true},
		{"hosts", parse_json_hosts, true},
	};

	result = handle_json_level_fields(handlers, parsed_json, app_config, nullptr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse JSON file");
		return result;
	}

	if (app_config->local_vf_addr.empty() || is_empty_mac_addr(app_config->dcap_dmac)) {
		DOCA_LOG_ERR("REQUIRED: One of (--vf-name) or (--decap-dmac + 'local-vip')");
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_DBG("Successfully parsed JSON file");

	return DOCA_SUCCESS;
}

/**
 * @brief Registers command-line arguments to the application.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t psp_gw_register_params(void)
{
	doca_error_t result;

	result = psp_gw_register_single_param("m",
					      "core-mask",
					      "EAL Core Mask",
					      handle_core_mask_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "decap-dmac",
					      "mac_dst addr of the decapped packets",
					      handle_decap_dmac_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("d",
					      "vf-name",
					      "Name of the virtual function device / unsecured port",
					      handle_vf_name_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("n",
					      "nexthop-dmac",
					      "next-hop mac_dst addr of the encapped packets",
					      handle_nexthop_dmac_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "cookie",
					      "Enable use of PSP virtualization cookies",
					      handle_vc_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("a",
					      "disable-ingress-acl",
					      "Allows any ingress packet that successfully decrypts",
					      handle_ingress_acl_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "sample-rate",
					      "Sets the log2 sample rate: 0: disabled, 1: 50%, ... 16: 1.5e-3%",
					      handle_sample_param,
					      DOCA_ARGP_TYPE_INT,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("x",
					      "max-tunnels",
					      "Specify the max number of PSP tunnels",
					      handle_max_tunnels_param,
					      DOCA_ARGP_TYPE_INT,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("o",
					      "crypt-offset",
					      "Specify the PSP crypt offset",
					      handle_psp_crypt_offset_param,
					      DOCA_ARGP_TYPE_INT,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "psp-version",
					      "Specify the PSP version for outgoing connections (0 or 1)",
					      handle_psp_version_param,
					      DOCA_ARGP_TYPE_INT,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("z",
					      "static-tunnels",
					      "Create tunnels at startup",
					      handle_static_tunnels_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("k",
					      "debug-keys",
					      "Enable debug keys",
					      handle_debug_keys_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "stat-print",
					      "Enable printing statistics",
					      handle_stats_print_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "perf-print",
					      "Enable printing performance metrics (key-gen, insertion, all)",
					      handle_perf_print_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "show-rss-rx-packets",
					      "Show RSS rx packets",
					      handle_show_rss_rx_packets_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param(nullptr,
					      "outer-ip-type",
					      "outer IP type",
					      handle_outer_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("c",
					      "config",
					      "Path to the JSON file with application configuration",
					      handle_config_file_param,
					      DOCA_ARGP_TYPE_STRING,
					      true,
					      false);

	return result;
}

doca_error_t psp_gw_argp_exec(int &argc, char *argv[], psp_gw_app_config *app_config)
{
	doca_error_t result;

	// Init ARGP interface and start parsing cmdline/json arguments
	result = doca_argp_init("doca_psp_gateway", app_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		return result;
	}

	result = psp_gw_register_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register ARGP parameters: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_error_get_descr(result));
		doca_argp_destroy();
		return result;
	}

	if (app_config->local_vf_addr.empty() || is_empty_mac_addr(app_config->dcap_dmac)) {
		DOCA_LOG_ERR("REQUIRED: One of (--vf-name) or (--decap-dmac + --local-virt-ip)");
		doca_argp_usage();
		doca_argp_destroy();
		return DOCA_ERROR_INVALID_VALUE;
	}

	char hostname[256];
	assert(gethostname(hostname, sizeof(hostname)) == 0);
	DOCA_LOG_INFO("PSP Gateway Service started on %s", hostname);
	app_config->hostname = hostname;

	return DOCA_SUCCESS;
}
