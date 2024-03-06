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

// system headers
#include <signal.h>
#include <fcntl.h>
#include <memory>

// dpdk
#include <rte_ethdev.h>

// doca
#include <dpdk_utils.h>
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>

#include <google/protobuf/util/json_util.h>
#include <grpcpp/server_builder.h>

// application
#include <psp_gw_config.h>
#include <psp_gw_bench.h>
#include <psp_gw_flows.h>
#include <psp_gw_svc_impl.h>
#include <psp_gw_params.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_utils.h>

DOCA_LOG_REGISTER(PSP_GATEWAY);

volatile bool force_quit; // Set when signal is received

/**
 * @brief Signal handler function (SIGINT and SIGTERM signals)
 *
 * @signum [in]: signal number
 */
static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		DOCA_LOG_INFO("Signal %d received, preparing to exit", signum);
		force_quit = true;
	}
}

// Function to check if a given device is capable of executing some task
typedef doca_error_t (*tasks_check)(struct doca_devinfo *);

/**
 * @brief Invokes doca_dev_open() on the netdev on the given PCI address
 *
 * @pci_addr [in]: The PCI DBDF or BDF address
 * @func [in]: Optional filtering function that checks the capability of matching devices
 * @retval [out]: The handle of the matching, now opened device
 * @return: EXIT_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func, struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	uint8_t is_addr_equal = 0;
	doca_error_t res;
	size_t i;

	/* Set default return value */
	*retval = NULL;

	res = doca_devinfo_create_list(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list. Doca_error value: %d", res);
		return res;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
		res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci_addr, &is_addr_equal);
		if (res == DOCA_SUCCESS && is_addr_equal) {
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS) {
				doca_devinfo_destroy_list(dev_list);
				return res;
			}
		}
	}

	DOCA_LOG_WARN("Matching device not found");
	res = DOCA_ERROR_NOT_FOUND;

	doca_devinfo_destroy_list(dev_list);
	return res;
}

/*
 * @brief PSP Gateway application main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int main(int argc, char **argv)
{
	doca_error_t result;
	int nb_ports = 2;
	int exit_status = EXIT_SUCCESS;

	struct psp_gw_app_config app_config = {
		.dpdk_config =
			{
				.port_config =
					{
						.nb_ports = nb_ports,
						.nb_queues = 2,
						.nb_hairpin_q = 2,
						.enable_mbuf_metadata = true,
						.isolated_mode = true,
					},
				.reserve_main_thread = true,
			},
		.pf_repr_indices = strdup("[0]"),
		.max_tunnels = 128,
		.net_config =
			{
				.hosts = {}, // filled by -t arguments
				.vc_enabled = true,
			},
		.log2_sample_rate = 1,
		.sample_meta_indicator = 0x43434343,
		.show_rss_rx_packets = true,
		.show_rss_durations = true,
	};

	struct psp_pf_dev pf_dev = {};
	uint16_t vf_port_id;
	std::string dev_probe_str;

	struct doca_log_backend *sdk_log;

	// Register a logger backend
	result = doca_log_backend_create_standard();
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	// Register a logger backend for internal SDK errors and warnings
	result = doca_log_backend_create_with_file_sdk(stdout, &sdk_log);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		return EXIT_FAILURE;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	result = psp_gw_argp_exec(argc, argv, &app_config);
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

	// init devices
	result = open_doca_device_with_pci(app_config.pf_pcie_addr.c_str(), nullptr, &pf_dev.dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open device %s: %s",
			     app_config.pf_pcie_addr.c_str(),
			     doca_error_get_descr(result));
		doca_argp_destroy();
		return EXIT_FAILURE;
	}

	dev_probe_str = std::string("dv_flow_en=2,"	 // hardware steering
				    "dv_xmeta_en=4,"	 // extended flow metadata support
				    "fdb_def_rule_en=0," // disable default root flow table rule
				    "vport_match=1,"
				    "repr_matching_en=0,") +
			app_config.pf_repr_indices; // indicate which representors to probe

	result = doca_dpdk_port_probe(pf_dev.dev, dev_probe_str.c_str());
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe dpdk port for secured port: %s", doca_error_get_descr(result));
		return result;
	}
	DOCA_LOG_INFO("Probed %s,%s", app_config.pf_pcie_addr.c_str(), dev_probe_str.c_str());

	pf_dev.port_id = 0;

	app_config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail();

	rte_eth_macaddr_get(pf_dev.port_id, &pf_dev.src_mac);
	result = doca_devinfo_get_ipv6_addr(doca_dev_as_devinfo(pf_dev.dev),
					    pf_dev.src_pip,
					    DOCA_DEVINFO_IPV6_ADDR_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to find IPv6 addr for PF: %s", doca_error_get_descr(result));
		return result;
	}

	pf_dev.src_mac_str = mac_to_string(pf_dev.src_mac);
	pf_dev.src_pip_str = ipv6_to_string(pf_dev.src_pip);
	DOCA_LOG_INFO("Port %d: Detected PF mac addr: %s, IPv6 addr: %s, total ports: %d",
		      pf_dev.port_id,
		      pf_dev.src_mac_str.c_str(),
		      pf_dev.src_pip_str.c_str(),
		      app_config.dpdk_config.port_config.nb_ports);

	vf_port_id = pf_dev.port_id + 1;

	// Update queues and ports
	result = dpdk_queues_and_ports_init(&app_config.dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_error_get_descr(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	if (app_config.run_benchmarks_and_exit) {
		app_config.max_tunnels = 64 * 1024;
		doca_log_level_set_global_lower_limit(DOCA_LOG_LEVEL_WARNING);
	}

	{
		PSP_GatewayFlows psp_flows(&pf_dev, vf_port_id, &app_config);

		result = psp_flows.init();
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to create flow pipes");
			exit_status = EXIT_FAILURE;
			goto dpdk_destroy;
		}

		if (app_config.run_benchmarks_and_exit) {
			psp_gw_run_benchmarks(&psp_flows);

		} else {
			PSP_GatewayImpl psp_svc(&app_config, &psp_flows);

			struct lcore_params lcore_params = {
				&force_quit,
				&app_config,
				&psp_flows,
				&psp_svc,
			};

			uint32_t lcore_id;
			RTE_LCORE_FOREACH_WORKER(lcore_id)
			{
				rte_eal_remote_launch(lcore_pkt_proc_func, &lcore_params, lcore_id);
			}

			std::string server_address = app_config.local_svc_addr;
			if (server_address.empty()) {
				server_address = "0.0.0.0";
			}
			if (server_address.find(":") == std::string::npos) {
				server_address += ":" + std::to_string(PSP_GatewayImpl::DEFAULT_HTTP_PORT_NUM);
			}
			grpc::ServerBuilder builder;
			builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
			builder.RegisterService(&psp_svc);
			auto server_instance = builder.BuildAndStart();
			std::cout << "Server listening on " << server_address << std::endl;

			// If configured to create all tunnels at startup, create a list of
			// pending tunnels here. Each invocation of try_connect will
			// remove entries from the list as tunnels are created.
			// Otherwise, this list will be left empty and tunnels will be created
			// on demand via the miss path.
			std::vector<psp_gw_host> remotes_to_connect;
			if (app_config.create_tunnels_at_startup) {
				remotes_to_connect = app_config.net_config.hosts;
			}

			while (!force_quit) {
				psp_svc.try_connect(remotes_to_connect);
				sleep(1);

				psp_flows.show_static_flow_counts();
				psp_svc.show_flow_counts();
			}

			DOCA_LOG_INFO("Shutting down");

			server_instance->Shutdown();
			server_instance.reset();

			RTE_LCORE_FOREACH_WORKER(lcore_id)
			{
				DOCA_LOG_INFO("Stopping L-Core %d", lcore_id);
				rte_eal_wait_lcore(lcore_id);
			}
		}
	}

	// flow cleanup
	dpdk_queues_and_ports_fini(&app_config.dpdk_config);

dpdk_destroy:
	dpdk_fini();
	doca_argp_destroy();

	return exit_status;
}
