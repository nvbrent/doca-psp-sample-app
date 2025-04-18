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

#include <algorithm>
#include <chrono>
#include <arpa/inet.h>
#include <doca_log.h>
#include <doca_flow_crypto.h>
#include <rte_lcore.h>

#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>

#include <psp_gw_svc_impl.h>
#include <psp_gw_config.h>
#include <psp_gw_flows.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_utils.h>
#include <algorithm>

DOCA_LOG_REGISTER(PSP_GW_SVC);

PSP_GatewayImpl::PSP_GatewayImpl(psp_gw_app_config *config)
	: config(config)
{
	config->crypto_ids_per_nic = config->max_tunnels + 1;

	for (psp_gw_nic_desc_t nic : config->net_config.local_nics) {
		psp_flows.push_back({
			nic.pip,
			new PSP_GatewayFlows(nic, config)
		});
	}

	assert(psp_flows.size() > 0);
}

PSP_GatewayImpl::~PSP_GatewayImpl()
{
	for (auto &pair : psp_flows) {
		delete pair.second;
	}
}

doca_error_t PSP_GatewayImpl::request_tunnels_to_host(const std::vector<psp_session_desc_t> &session_descs)
{
	std::vector<doca_error_t> results;

	if (session_descs.size() == 0) {
		return DOCA_SUCCESS;
	}

	PSP_GatewayFlows *nic = lookup_flows(session_descs[0].local_vip);
	if (!nic) {
		DOCA_LOG_ERR("No NIC found for local VIP %s", session_descs[0].local_vip.c_str());
		return DOCA_ERROR_BAD_STATE;
	}

	std::vector<spi_key_t> ingress_spi_keys;
	results = nic->create_ingress_paths(session_descs, ingress_spi_keys);
	if (check_any_failed(results)) {
		DOCA_LOG_ERR("Failed to create new ingress paths");
		return DOCA_ERROR_BAD_STATE;
	}

	::grpc::ClientContext context;
	std::vector<bool> remote_updated(session_descs.size(), false);
	for (size_t i = 0; i < session_descs.size(); i++) {
		::psp_gateway::MultiTunnelRequest request;
		::psp_gateway::SingleTunnelRequest *single_request = request.add_tunnels();

		psp_gw_nic_desc_t *remote_nic = lookup_nic(session_descs[i].remote_vip);
		auto *stub = get_stub(remote_nic->svc_ip_str);

		request.add_psp_versions_accepted(config->net_config.default_psp_proto_ver);
		single_request->set_virt_src_ip(session_descs[i].local_vip);
		single_request->set_virt_dst_ip(session_descs[i].remote_vip);
		fill_tunnel_params(
			&ingress_spi_keys[i].key[0],
			ingress_spi_keys[i].spi,
			nic->get_pip(),
			single_request->mutable_reverse_params());

		::psp_gateway::MultiTunnelResponse response;
		::grpc::Status status = stub->RequestMultipleTunnelParams(&context, request, &response);
		if (!status.ok()) {
			DOCA_LOG_ERR("Failed to request tunnel to %s: %s", session_descs[i].remote_vip.c_str(), status.error_message().c_str());
		} else {
			remote_updated[i] = true;

			spi_keyptr_t spi_key;
			spi_key.spi = response.tunnels_params(0).spi();
			spi_key.key = (void *)response.tunnels_params(0).encryption_key().c_str();

			std::vector<spi_keyptr_t> egress_spi_keys = {spi_key};
			std::vector<psp_session_desc_t> egress_sessions = {session_descs[i]};
			results = nic->set_egress_paths(egress_sessions, egress_spi_keys);
			if (check_any_failed(results)) {
				DOCA_LOG_ERR("Failed to set egress paths for %s", session_descs[i].remote_vip.c_str());
			}
		}
	}

	results = nic->expire_ingress_paths(session_descs, remote_updated);
	if (check_any_failed(results)) {
		DOCA_LOG_WARN("Failed to expire old ingress paths");
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayImpl::handle_miss_packet(struct rte_mbuf *packet)
{

	if (config->create_tunnels_at_startup)
		return DOCA_SUCCESS; // no action; tunnels to be created by the main loop

	const auto *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	if (eth_hdr->ether_type != RTE_BE16(RTE_ETHER_TYPE_IPV4))
		return DOCA_SUCCESS; // no action

	const auto *ipv4_hdr = rte_pktmbuf_mtod_offset(packet, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	psp_session_desc_t session_desc;
	session_desc.local_vip = ipv4_to_string(ipv4_hdr->src_addr);
	session_desc.remote_vip = ipv4_to_string(ipv4_hdr->dst_addr);
	psp_gw_nic_desc_t *remote_nic = lookup_nic(session_desc.remote_vip);
	if (remote_nic == nullptr) {
		DOCA_LOG_ERR("No NIC found for remote VIP %s", session_desc.remote_vip.c_str());
		return DOCA_ERROR_BAD_STATE;
	}
	session_desc.remote_pip = remote_nic->pip;

	std::vector<psp_session_desc_t> session_descs = {session_desc};
	doca_error_t result = request_tunnels_to_host(session_descs);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to request tunnel to %s", session_desc.remote_vip.c_str());
		return result;
	}

	return result;
}


::grpc::Status PSP_GatewayImpl::RequestMultipleTunnelParams(::grpc::ServerContext *context,
							    const ::psp_gateway::MultiTunnelRequest *request,
							    ::psp_gateway::MultiTunnelResponse *response)
{
	if (request->tunnels_size() == 0) {
		DOCA_LOG_WARN("Request received with no tunnels");
		return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "No tunnels requested");
	}

	std::vector<psp_session_desc_t> relevant_sessions(request->tunnels_size());
	std::vector<spi_keyptr_t> egress_spi_keys(request->tunnels_size());
	for (int i = 0; i < request->tunnels_size(); i++) {
		const auto &tunnel_request = request->tunnels(i);

		relevant_sessions[i].remote_pip = tunnel_request.reverse_params().ip_addr();
		relevant_sessions[i].remote_vip = tunnel_request.virt_src_ip();
		relevant_sessions[i].local_vip = tunnel_request.virt_dst_ip();

		egress_spi_keys[i].spi = tunnel_request.reverse_params().spi();
		egress_spi_keys[i].key = (void *)tunnel_request.reverse_params().encryption_key().c_str();
	}

	// If/when we decide we want to support multiple NIC flow updates in a single request, we can do it here
	PSP_GatewayFlows *nic = lookup_flows(relevant_sessions[0].local_vip);
	if (!nic) {
		DOCA_LOG_ERR("No NIC found for local VIP %s", relevant_sessions[0].local_vip.c_str());
		return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "No NIC found for local VIP");
	}

	std::vector<doca_error_t> results;
	results = nic->set_egress_paths(relevant_sessions, egress_spi_keys);
	if (check_any_failed(results)) {
		return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "Failed to set egress paths");
	}

	std::vector<spi_key_t> ingress_spi_keys;
	results = nic->create_ingress_paths(relevant_sessions, ingress_spi_keys);
	if (check_any_failed(results)) {
		return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "Failed to create new ingress paths");
	}

	response->set_request_id(request->request_id());
	for (size_t i = 0; i < relevant_sessions.size(); i++) {
		fill_tunnel_params(
			&ingress_spi_keys[i].key[0],
			ingress_spi_keys[i].spi,
			nic->get_pip(),
			response->add_tunnels_params());
	}

	std::vector<bool> remote_updated(relevant_sessions.size(), true);
	for (doca_error_t result : results) {
		remote_updated.push_back(result == DOCA_SUCCESS);
	}
	results = nic->expire_ingress_paths(relevant_sessions, remote_updated);
	if (check_any_failed(results)) {
		return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "Failed to expire old ingress paths");
	}

	return ::grpc::Status::OK;
}


::grpc::Status PSP_GatewayImpl::RequestKeyRotation(::grpc::ServerContext *context,
						   const ::psp_gateway::KeyRotationRequest *request,
						   ::psp_gateway::KeyRotationResponse *response)
{
	(void)context;
	DOCA_LOG_DBG("Received PSP Master Key Rotation Request");

	response->set_request_id(request->request_id());


	for (auto &pair : psp_flows) {
		std::vector<psp_session_desc_t> curr_ingress_sessions;
		pair.second->rotate_master_key(curr_ingress_sessions);

		if (!request->issue_new_keys() || curr_ingress_sessions.empty()) {
			continue;
		}
		// Request new tunnels to the host with the new key
		doca_error_t result = request_tunnels_to_host(curr_ingress_sessions);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to update tunnels after key rotation");
		}
	}

	return ::grpc::Status::OK;
}

::grpc::Status PSP_GatewayImpl::SetOpState(::grpc::ServerContext *context,
					   const ::psp_gateway::OpStateMsg *request,
					   ::psp_gateway::OpStateMsg *response)
{
	using namespace std::chrono;
	auto tstart = high_resolution_clock::now();
	auto expiration = tstart + seconds(1);
	auto op_state = (doca_flow_port_operation_state)request->op_state();

	for (auto &pair : psp_flows) {
		pair.second->set_pending_op_state(op_state);
		// the lcore threads should call apply_pending_op_state() via lcore_callback()
	}

	bool done = false;
	while (!done && high_resolution_clock::now() < expiration) {
		done = std::all_of(psp_flows.begin(), psp_flows.end(), [](auto &pair){
			return !pair.second->has_pending_op_state();
		});
	}
	if (!done) {
		std::string error = "Timed out waiting for op_state change";
		DOCA_LOG_ERR("%s", error.c_str());
		return ::grpc::Status(::grpc::StatusCode::DEADLINE_EXCEEDED, error);
	}

	auto dur = high_resolution_clock::now() - tstart;
	DOCA_LOG_INFO("Change of op_state: took %ld milliseconds",
		duration_cast<milliseconds>(dur).count());
	response->set_op_state(request->op_state());
	return ::grpc::Status::OK;
}

::grpc::Status PSP_GatewayImpl::GetOpState(::grpc::ServerContext *context,
					 const ::psp_gateway::OpStateMsg *request,
					 ::psp_gateway::OpStateMsg *response)
{
	response->set_op_state((psp_gateway::OpState)psp_flows.front().second->get_op_state());
	return ::grpc::Status::OK;
}

size_t PSP_GatewayImpl::try_connect(std::vector<psp_gw_nic_desc_t> &hosts, rte_be32_t local_vf_addr)
{
	size_t num_connected = 0;
	// for (auto host_iter = hosts.begin(); host_iter != hosts.end(); /* increment below */) {
	// 	doca_error_t result = request_tunnel_to_host(&*host_iter, local_vf_addr, 0, false, true, false);
	// 	if (result == DOCA_SUCCESS) {
	// 		++num_connected;
	// 		host_iter = hosts.erase(host_iter);
	// 	} else {
	// 		++host_iter;
	// 	}
	// }
	return num_connected;
}

doca_error_t PSP_GatewayImpl::show_flow_counts(void)
{

	for (auto &pair : psp_flows) {
		pair.second->show_static_flow_counts();
		pair.second->show_session_flow_counts();
	}
	return DOCA_SUCCESS;
}


::psp_gateway::PSP_Gateway::Stub *PSP_GatewayImpl::get_stub(const std::string &remote_host_ip)
{
	auto stubs_iter = stubs.find(remote_host_ip);
	if (stubs_iter != stubs.end()) {
		return stubs_iter->second.get();
	}

	std::string remote_host_addr = remote_host_ip;
	if (remote_host_addr.find(":") == std::string::npos) {
		remote_host_addr += ":" + std::to_string(DEFAULT_HTTP_PORT_NUM);
	}
	auto channel = grpc::CreateChannel(remote_host_addr, grpc::InsecureChannelCredentials());
	stubs_iter = stubs.emplace(remote_host_ip, psp_gateway::PSP_Gateway::NewStub(channel)).first;

	DOCA_LOG_INFO("Created gRPC stub for remote host %s", remote_host_addr.c_str());

	return stubs_iter->second.get();
}

doca_error_t PSP_GatewayImpl::init_devs(void) {
	doca_error_t result = DOCA_SUCCESS;
	DOCA_LOG_INFO("Initializing PSP Gateway Devices");

	const char *eal_args[] = {"", "-a00:00.0", "-c", config->core_mask.c_str(), "--file-prefix", std::to_string(getpid()).c_str()};

	int n_eal_args = sizeof(eal_args) / sizeof(eal_args[0]);
	int rc = rte_eal_init(n_eal_args, (char **)eal_args);
	if (rc < 0) {
		DOCA_LOG_ERR("EAL initialization failed: %d", rc);
		for (int i = 0; i < n_eal_args; i++) {
			DOCA_LOG_ERR("EAL arg %d: %s", i, eal_args[i]);
		}
		return DOCA_ERROR_BAD_STATE;
	}

	for (auto &pair : psp_flows) {
		IF_SUCCESS(result, pair.second->init_dev());
	}
	return result;
}

doca_error_t PSP_GatewayImpl::init_flows(void) {
	doca_error_t result = DOCA_SUCCESS;

	IF_SUCCESS(result, init_doca_flow());
	for (auto &pair : psp_flows) {
		IF_SUCCESS(result, pair.second->init_flows());
	}

	return result;
}

doca_error_t PSP_GatewayImpl::init_doca_flow(void)
{
	doca_error_t result = DOCA_SUCCESS;
	uint16_t nb_queues = config->dpdk_config.port_config.nb_queues;

	uint16_t rss_queues[nb_queues];
	for (int i = 0; i < nb_queues; i++)
		rss_queues[i] = i;

	struct doca_flow_resource_rss_cfg rss_config = {};
	rss_config.nr_queues = nb_queues;
	rss_config.queues_array = rss_queues;

	size_t nb_nics = psp_flows.size();

	/* init doca flow with crypto shared resources */
	struct doca_flow_cfg *flow_cfg;
	IF_SUCCESS(result, doca_flow_cfg_create(&flow_cfg));
	IF_SUCCESS(result, doca_flow_cfg_set_pipe_queues(flow_cfg, nb_queues));
	IF_SUCCESS(result, doca_flow_cfg_set_nr_counters(flow_cfg, nb_nics * config->max_tunnels * NUM_OF_PSP_SYNDROMES + 10));
	IF_SUCCESS(result, doca_flow_cfg_set_mode_args(flow_cfg, "switch,hws,isolated,expert"));
	IF_SUCCESS(result, doca_flow_cfg_set_cb_entry_process(flow_cfg, PSP_GatewayImpl::check_for_valid_entry));
	IF_SUCCESS(result, doca_flow_cfg_set_default_rss(flow_cfg, &rss_config));
	IF_SUCCESS(result,
		   doca_flow_cfg_set_nr_shared_resource(flow_cfg,
							config->crypto_ids_per_nic * nb_nics,
							DOCA_FLOW_SHARED_RESOURCE_PSP));
	IF_SUCCESS(result, doca_flow_cfg_set_nr_shared_resource(flow_cfg, 4 * nb_nics, DOCA_FLOW_SHARED_RESOURCE_MIRROR));
	IF_SUCCESS(result, doca_flow_init(flow_cfg));

	if (result == DOCA_SUCCESS)
		DOCA_LOG_INFO("Initialized DOCA Flow for a max of %d tunnels", config->max_tunnels);

	if (flow_cfg)
		doca_flow_cfg_destroy(flow_cfg);
	return result;
}

void PSP_GatewayImpl::launch_lcores(volatile bool *force_quit) {
	uint32_t lcore_id;

	lcore_params_list.reserve(rte_lcore_count());
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		struct lcore_params lcore_params = {
			force_quit,
			config,
			0, // pf port id
			this,
		};

		lcore_params_list.push_back(lcore_params);
		rte_eal_remote_launch(lcore_pkt_proc_func, &lcore_params_list.back(), lcore_id);
	}
}

void PSP_GatewayImpl::lcore_callback()
{
	// Note lcore_id==0 is reserved for main()
	uint32_t lcore_id = rte_lcore_id() - 1;
	uint32_t lcore_count = rte_lcore_count() - 1;

	for (uint32_t nic_idx=lcore_id; nic_idx<psp_flows.size(); nic_idx += lcore_count) {
		doca_error_t result = psp_flows[nic_idx].second->apply_pending_op_state();
		if (result != DOCA_SUCCESS && result != DOCA_ERROR_SKIPPED) {
			DOCA_LOG_ERR("Failed to set operational state: %d (%s)", result, doca_error_get_descr(result));

		}
	}
}

void PSP_GatewayImpl::kill_lcores() {
	uint32_t lcore_id;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		DOCA_LOG_INFO("Stopping L-Core %d", lcore_id);
		rte_eal_wait_lcore(lcore_id);
	}

	lcore_params_list.clear();
}

/*
 * Entry processing callback
 *
 * @entry [in]: entry pointer
 * @pipe_queue [in]: queue identifier
 * @status [in]: DOCA Flow entry status
 * @op [in]: DOCA Flow entry operation
 * @user_ctx [out]: user context
 */
void PSP_GatewayImpl::check_for_valid_entry(doca_flow_pipe_entry *entry,
					     uint16_t pipe_queue,
					     enum doca_flow_entry_status status,
					     enum doca_flow_entry_op op,
					     void *user_ctx)
{
	(void)entry;
	(void)op;
	(void)pipe_queue;

	auto *entry_status = (entries_status *)user_ctx;

	if (entry_status == NULL)
		return;

	if (op != DOCA_FLOW_ENTRY_OP_ADD && op != DOCA_FLOW_ENTRY_OP_UPD)
		return;

	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		entry_status->failure = true; /* set failure to true if processing failed */

	entry_status->nb_processed++;
	entry_status->entries_in_queue--;
}

void PSP_GatewayImpl::fill_tunnel_params(uint32_t *key, uint32_t spi, std::string local_pip, psp_gateway::TunnelParameters *params)
{
	uint32_t key_len_bits = psp_version_to_key_length_bits(config->net_config.default_psp_proto_ver);
	uint32_t key_len_bytes = key_len_bits / 8;

	params->set_psp_version(config->net_config.default_psp_proto_ver);
	params->set_spi(spi);
	params->set_encryption_key(key, key_len_bytes);

	if (config->outer == DOCA_FLOW_L3_TYPE_IP4)
		params->set_encap_type(4);
	else
		params->set_encap_type(6);

	params->set_ip_addr(local_pip);

	params->set_virt_cookie(0x778899aabbccddee);
	params->set_mac_addr("aa:bb:cc:dd:ee:ff");
}

psp_gw_nic_desc_t *
PSP_GatewayImpl::lookup_nic(std::string vip_to_find)
{
	struct psp_gw_net_config *net_config = &config->net_config;

	// Search the cache for a quicker lookup
	auto vip_nic_iter = net_config->vip_nic_lookup.find(vip_to_find);
	if (vip_nic_iter != net_config->vip_nic_lookup.end()) {
		return vip_nic_iter->second;
	}

	// Search the list of local nics
	for (psp_gw_nic_desc_t &nic : net_config->local_nics) {
		for (std::string &vip : nic.vips) {
			if (vip == vip_to_find) {
				net_config->vip_nic_lookup[vip_to_find] = &nic;
				return &nic;
			}
		}
	}

	// Search the list of remote nics
	for (psp_gw_nic_desc_t &nic : net_config->remote_nics) {
		for (std::string &vip : nic.vips) {
			if (vip == vip_to_find) {
				net_config->vip_nic_lookup[vip_to_find] = &nic;
				return &nic;
			}
		}
	}

	assert(false);
	return nullptr;
}

PSP_GatewayFlows*
PSP_GatewayImpl::lookup_flows(std::string local_vip)
{
	struct psp_gw_nic_desc_t *nic = lookup_nic(local_vip);
	if (nic == nullptr) {
		DOCA_LOG_ERR("No NIC found for local VIP %s", local_vip.c_str());
		return nullptr;
	}

	for (auto &pair : psp_flows) {
		if (pair.first == nic->pip) {
			return pair.second;
		}
	}

	DOCA_LOG_ERR("No flows found for local NIC %s", local_vip.c_str());
	assert(false);
	return nullptr;
}
