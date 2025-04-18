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

// system headers
#include <signal.h>
#include <fcntl.h>
#include <memory>

// dpdk
#include <rte_ethdev.h>
#include <rte_version.h>

// doca
#include <dpdk_utils.h>
#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_flow.h>
#include <doca_log.h>
#include <doca_dpdk.h>
#include <samples/common.h>

#include <google/protobuf/util/json_util.h>
#include <grpcpp/server_builder.h>

// application
#include <psp_gw_config.h>
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

	struct psp_gw_app_config app_config = {};
	app_config.dpdk_config.port_config.nb_ports = nb_ports;
	app_config.dpdk_config.port_config.nb_queues = 2;
	app_config.dpdk_config.port_config.switch_mode = true;
	app_config.dpdk_config.port_config.enable_mbuf_metadata = true;
	app_config.dpdk_config.port_config.isolated_mode = true;
	app_config.dpdk_config.reserve_main_thread = true;
	app_config.core_mask = strdup("0x1ff");
	app_config.max_tunnels = 128;
	app_config.net_config.vc_enabled = false;
	app_config.net_config.crypt_offset = app_config.net_config.vc_enabled ? DEFAULT_CRYPT_OFFSET_VC_ENABLED : DEFAULT_CRYPT_OFFSET;
	app_config.net_config.default_psp_proto_ver = DEFAULT_PSP_VERSION;
	app_config.log2_sample_rate = 0;
	app_config.ingress_sample_meta_indicator = 0x65656565; // arbitrary pkt_meta flag value
	app_config.egress_sample_meta_indicator = 0x43434343;
	app_config.show_sampled_packets = true;
	app_config.show_rss_rx_packets = false;
	app_config.show_rss_durations = false;
	app_config.outer = DOCA_FLOW_L3_TYPE_IP6;
	app_config.next_crypto_id = 0;
	app_config.next_mirror_id = 1;
	app_config.next_port_id = 0;

	struct psp_pf_dev pf_dev = {};
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

	DOCA_LOG_INFO("doca-flow version: %s", doca_version());
	DOCA_LOG_INFO("libdpdk version: %s", rte_version());

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	result = psp_gw_argp_exec(argc, argv, &app_config);
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

	result = psp_gw_parse_config_file(&app_config);
	if (result != DOCA_SUCCESS) {
		return EXIT_FAILURE;
	}

	PSP_GatewayImpl psp_svc(&app_config);

	// probe devices
	result = psp_svc.init_devs();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe device");
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	app_config.dpdk_config.port_config.nb_ports = rte_eth_dev_count_avail();

	// Update queues and ports
	result = dpdk_queues_and_ports_init(&app_config.dpdk_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update application ports and queues: %s", doca_error_get_descr(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	// initialize static pipeline
	result = psp_svc.init_flows();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to initialize PSP Gateway Flows: %s", doca_error_get_descr(result));
		exit_status = EXIT_FAILURE;
		goto dpdk_destroy;
	}

	{
		psp_svc.launch_lcores(&force_quit);

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
		std::vector<psp_gw_nic_desc_t> remotes_to_connect;
		rte_be32_t local_vf_addr = 0;
		if (app_config.create_tunnels_at_startup) {
			if (inet_pton(AF_INET, app_config.local_vf_addr.c_str(), &local_vf_addr) != 1) {
				DOCA_LOG_ERR("Invalid local_vf_addr: %s", app_config.local_vf_addr.c_str());
				exit_status = EXIT_FAILURE;
				goto dpdk_destroy;
			}
			remotes_to_connect = app_config.net_config.remote_nics;
		}

		while (!force_quit) {
			psp_svc.try_connect(remotes_to_connect, local_vf_addr);
			sleep(1);

			if (app_config.print_stats) {
				psp_svc.show_flow_counts();
			}
		}

		DOCA_LOG_INFO("Shutting down");

		server_instance->Shutdown();
		server_instance.reset();

		psp_svc.kill_lcores();
	}

	// flow cleanup
	dpdk_queues_and_ports_fini(&app_config.dpdk_config);

dpdk_destroy:
	dpdk_fini();
	doca_argp_destroy();

	return exit_status;
}
