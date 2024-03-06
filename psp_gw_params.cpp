/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <ctype.h>
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>

#include <psp_gw_config.h>
#include <psp_gw_params.h>

DOCA_LOG_REGISTER(PSP_Gateway_Params);

using dev_pci_addr_devarg = std::pair<std::string, std::string>;

/**
 * @brief Parses a tunnel specifier for a remote host
 *
 * @fields [in]: A comma-separated string containing the following:
 * - rpc_ipv4_addr
 * - virt_ipv4_addr
 * @host [out]: The host data structure to populate
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static bool parse_host_param(char *fields, struct psp_gw_host *host)
{
	char *svcaddr = strtok_r(fields, ",", &fields);
	char *virt_ip = strtok_r(fields, ",", &fields);
	char *extra_field_check = strtok_r(fields, ",", &fields); // expect null

	if (!svcaddr || !virt_ip || extra_field_check) {
		DOCA_LOG_ERR("Tunnel host requires 2 args: svc_ip,vip");
		return false;
	}
	if (inet_pton(AF_INET, svcaddr, &host->svc_ip) != 1) {
		DOCA_LOG_ERR("Invalid svc IPv4 addr: %s", svcaddr);
		return false;
	}
	if (inet_pton(AF_INET, virt_ip, &host->vip) != 1) {
		DOCA_LOG_ERR("Invalid virtual IPv4 addr: %s", virt_ip);
		return false;
	}
	return true;
}

/**
 * @brief Adds a tunnel specifier for a given remote host
 *
 * @param [in]: A string of the form described in parse_host_param()
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_host_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	char *host_params = (char *)param;
	struct psp_gw_host host = {};

	// note commas in host_params are replaced by null character
	if (!parse_host_param(host_params, &host)) {
		return DOCA_ERROR_INVALID_VALUE; // details already logged
	}

	app_config->net_config.hosts.push_back(host);

	DOCA_LOG_INFO("Added Host %d: %s",
		      (int)app_config->net_config.hosts.size(),
		      host_params); // just the svc addr, due to strtok
	return DOCA_SUCCESS;
}

/**
 * @brief Indicates the preferred socket address of the gRPC server
 *
 * @param [in]: A string containing an IPv4 address and optionally
 *              a colon character and port number
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_svc_addr_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	app_config->local_svc_addr = (char *)param;

	DOCA_LOG_INFO("Selected local Svc Addr: %s", app_config->local_svc_addr.c_str());
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
 * @brief Indicates the application should execute benchmarks
 *
 * @param [in]: A pointer to a boolean flag
 * @config [in/out]: A void pointer to the application config struct
 * @return: DOCA_SUCCESS on success; DOCA_ERROR otherwise
 */
static doca_error_t handle_benchmark_param(void *param, void *config)
{
	auto *app_config = (struct psp_gw_app_config *)config;
	bool *bool_param = (bool *)param;
	app_config->run_benchmarks_and_exit = *bool_param;
	DOCA_LOG_INFO("PSP Benchmarking %s", *bool_param ? "Enabled" : "Disabled");
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
	bool *bool_param = (bool *)param;
	app_config->create_tunnels_at_startup = *bool_param;
	DOCA_LOG_INFO("Create PSP tunnels at startup: %s", *bool_param ? "Enabled" : "Disabled");
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
 * @brief Registers command-line arguments to the application.
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t psp_gw_register_params(void)
{
	doca_error_t result;

	result = psp_gw_register_single_param("s",
					      "svc-addr",
					      "Service address of locally running gRPC server; port number optional",
					      handle_svc_addr_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("t",
					      "tunnel",
					      "Remote host tunnel(s), formatted 'mac-addr,phys-ip,virt-ip'",
					      handle_host_param,
					      DOCA_ARGP_TYPE_STRING,
					      false,
					      true);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("c",
					      "cookie",
					      "Enable use of PSP virtualization cookies",
					      handle_vc_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
					      false,
					      false);
	if (result != DOCA_SUCCESS)
		return result;

	result = psp_gw_register_single_param("b",
					      "benchmark",
					      "Run PSP Benchmarks and exit",
					      handle_benchmark_param,
					      DOCA_ARGP_TYPE_BOOLEAN,
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

	return result;
}

static dev_pci_addr_devarg split_pci_devargs(std::string dev_params)
{
	// skip any -a prefix
	size_t start = (dev_params[0] == '-' && dev_params[1] == 'a') ? 2 : 0;
	for (size_t i = start; i < dev_params.size(); i++) {
		if (dev_params[i] == ',') {
			// split the params here and return
			return {dev_params.substr(start, i - start), dev_params.substr(i + 1)};
		}
		// open_doca_device_with_pci() requires lowercase address characters
		dev_params[i] = tolower(dev_params[i]);
	}

	// no comma found:
	return {dev_params.substr(start), ""};
}

/**
 * @brief Iterates through the program argv list, removing any which start with -a
 * and returning them via the dev_allowlist_args output vector.
 *
 * @argc [in]: The number of args passed to main()
 * @argv [in/out]: The args passed to main (input), with all -a args removed (output)
 * @return: The list of arguments removed from argv in the form of
 * pci_dbdf,devargs
 */
static std::vector<dev_pci_addr_devarg> psp_gw_separate_dev_allowlist_args(int argc, char *argv[])
{
	std::vector<dev_pci_addr_devarg> dev_allowlist_args;

	bool next_is_pci_addr = false; // set whenever -a and the addr arg are separated by space
	static char null_pci_devarg[] = "-a00:00.0";
	static char null_pci_dev[] = "00:00.0";

	for (int i = 0; i < argc; i++) {
		if (next_is_pci_addr) {
			// prev arg was -a by itself, now we need the device PCI addr
			dev_allowlist_args.push_back(split_pci_devargs(argv[i]));
			next_is_pci_addr = false;
			argv[i] = null_pci_dev;
		} else if (strncmp(argv[i], "-a", 2) == 0) {
			next_is_pci_addr = strlen(argv[i]) == 2;
			if (!next_is_pci_addr) {
				dev_allowlist_args.push_back(split_pci_devargs(argv[i]));
				argv[i] = null_pci_devarg;
			}
		}
	}

	return dev_allowlist_args;
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

	doca_argp_set_dpdk_program(dpdk_init);

	auto dev_allowlist_args = psp_gw_separate_dev_allowlist_args(argc, argv);
	if (dev_allowlist_args.empty()) {
		DOCA_LOG_ERR("One PCIe device must be specified via EAL arg -a");
		return result;
	}

	app_config->pf_pcie_addr = dev_allowlist_args[0].first;
	app_config->pf_repr_indices = dev_allowlist_args[0].second;
	if (app_config->pf_repr_indices.empty())
		app_config->pf_repr_indices = "representor=0";

	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse application input: %s", doca_error_get_descr(result));
		doca_argp_destroy();
		return result;
	}

	return DOCA_SUCCESS;
}
