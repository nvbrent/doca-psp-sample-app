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

#include <arpa/inet.h>
#include <doca_log.h>
#include <doca_flow_crypto.h>

#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>

#include <psp_gw_svc_impl.h>
#include <psp_gw_config.h>
#include <psp_gw_flows.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_utils.h>

DOCA_LOG_REGISTER(PSP_GW_SVC);

PSP_GatewayImpl::PSP_GatewayImpl(psp_gw_app_config *config, PSP_GatewayFlows *psp_flows)
	: config(config),
	  psp_flows(psp_flows),
	  pf(psp_flows->pf()),
	  DEBUG_KEYS(config->debug_keys)
{
	if (DEBUG_KEYS) {
		DOCA_LOG_INFO("NOTE: DEBUG_KEYS is enabled; crypto keys will be written to logs.");
	}
}

doca_error_t PSP_GatewayImpl::handle_miss_packet(struct rte_mbuf *packet)
{
	if (config->create_tunnels_at_startup)
		return DOCA_SUCCESS; // no action; tunnels to be created by the main loop

	const auto *eth_hdr = rte_pktmbuf_mtod(packet, struct rte_ether_hdr *);
	if (eth_hdr->ether_type != RTE_BE16(RTE_ETHER_TYPE_IPV4))
		return DOCA_SUCCESS; // no action

	const auto *ipv4_hdr = rte_pktmbuf_mtod_offset(packet, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

	std::string dst_vip = ipv4_to_string(ipv4_hdr->dst_addr);

	// Create the new tunnel instance, if one does not already exist
	if (sessions.count(dst_vip) == 0) {
		// Determine the peer which owns the virtual destination
		auto *remote_host = lookup_remote_host(ipv4_hdr->dst_addr);
		if (!remote_host) {
			DOCA_LOG_WARN("Virtual Destination IP Addr not found: %s", dst_vip.c_str());
			return DOCA_ERROR_NOT_FOUND;
		}

		doca_error_t result = request_tunnel_to_host(remote_host, ipv4_hdr->src_addr, false);
		if (result != DOCA_SUCCESS) {
			return result;
		}
	}

	// A new tunnel was created; we can now resubmit the packet
	// and it will be encrypted and sent to the right port.
	if (!reinject_packet(packet, pf->port_id)) {
		std::string src_vip = ipv4_to_string(ipv4_hdr->src_addr);
		DOCA_LOG_ERR("Failed to resubmit packet from vnet addr %s to %s on port %d",
			     src_vip.c_str(),
			     dst_vip.c_str(),
			     pf->port_id);
		return DOCA_ERROR_FULL;
	}
	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayImpl::request_tunnel_to_host(struct psp_gw_host *remote_host,
						     doca_be32_t local_virt_ip,
						     bool suppress_failure_msg)
{
	std::string remote_host_svc_pip = ipv4_to_string(remote_host->svc_ip);
	std::string remote_host_vip = ipv4_to_string(remote_host->vip);
	std::string local_vip = ipv4_to_string(local_virt_ip);

	auto *stub = get_stub(remote_host_svc_pip);

	::grpc::ClientContext context;
	::psp_gateway::NewTunnelRequest request;
	request.set_request_id(++next_request_id);
	request.add_psp_versions_accepted(SUPPORTED_PSP_VER);
	request.set_virt_src_ip(local_vip);
	request.set_virt_dst_ip(remote_host_vip);

	// Save a round-trip, if a local virtual IP was given.
	// Otherwise, expect the remote host to send a separate request.
	if (local_virt_ip) {
		doca_error_t result = generate_tunnel_params(request.mutable_reverse_params());
		if (result != DOCA_SUCCESS) {
			return result;
		}
	}

	::psp_gateway::NewTunnelResponse response;
	::grpc::Status status = stub->RequestTunnelParams(&context, request, &response);

	if (!status.ok()) {
		if (!suppress_failure_msg) {
			DOCA_LOG_ERR("Request for new SPI/Key to remote host %s failed: %s",
				     remote_host_svc_pip.c_str(),
				     status.error_message().c_str());
		}
		return DOCA_ERROR_IO_FAILED;
	}

	return create_tunnel_flow(remote_host, request.request_id(), response.params());
}

doca_error_t PSP_GatewayImpl::create_tunnel_flow(const struct psp_gw_host *remote_host,
						 uint64_t request_id,
						 const psp_gateway::TunnelParameters &params)
{
	std::string remote_host_svc_ip = ipv4_to_string(remote_host->svc_ip);
	std::string remote_host_vip = ipv4_to_string(remote_host->vip);

	if (params.encryption_key().size() != key_len_bytes) {
		DOCA_LOG_ERR("Request for new SPI/Key to remote host %s failed: %s (%ld)",
			     remote_host_svc_ip.c_str(),
			     "Invalid encryption key length",
			     params.encryption_key().size() * 8);
		return DOCA_ERROR_IO_FAILED;
	}

	uint32_t crypto_id = next_crypto_id();
	if (crypto_id == UINT32_MAX) {
		DOCA_LOG_ERR("Exhausted available crypto_ids; cannot complete new tunnel");
		return DOCA_ERROR_NO_MEMORY;
	}

	const void *encrypt_key = params.encryption_key().c_str();

	psp_session_t &session = sessions[remote_host_vip];
	session = (struct psp_session_t){
		.dst_vip = remote_host->vip,
		.spi = params.spi(),
		.crypto_id = crypto_id,
		.vc = params.virt_cookie(),
	};
	rte_ether_unformat_addr(params.mac_addr().c_str(), &session.dst_mac);
	inet_pton(AF_INET6, params.ip_addr().c_str(), session.dst_pip);

	DOCA_LOG_INFO("Received tunnel params from %s, SPI %d", remote_host_svc_ip.c_str(), session.spi);
	debug_key(encrypt_key, params.encryption_key().size());

	doca_error_t result = psp_flows->add_encrypt_entry(&session, encrypt_key);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create session from %s request %ld: %s",
			     remote_host_svc_ip.c_str(),
			     request_id,
			     doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

int PSP_GatewayImpl::is_version_supported(const ::psp_gateway::NewTunnelRequest *request) const
{
	for (int ver : request->psp_versions_accepted()) {
		if (ver == SUPPORTED_PSP_VER)
			return ver;
	}
	return -1;
}

::grpc::Status PSP_GatewayImpl::RequestTunnelParams(::grpc::ServerContext *context,
						    const ::psp_gateway::NewTunnelRequest *request,
						    ::psp_gateway::NewTunnelResponse *response)
{
	doca_error_t result;

	std::string peer = context ? context->peer() // note: NOT authenticated
				     :
				     "[TESTING]";

	response->set_request_id(request->request_id());

	if (!is_version_supported(request)) {
		DOCA_LOG_ERR("Rejecting tunnel request from peer %s, Requires PSP ver. 1", peer.c_str());
		return ::grpc::Status(::grpc::INVALID_ARGUMENT, "Requires PSP ver. 1");
	}

	result = generate_tunnel_params(response->mutable_params());
	if (result != DOCA_SUCCESS) {
		return ::grpc::Status(::grpc::RESOURCE_EXHAUSTED, "Failed to generate SPI/Key");
	}

	DOCA_LOG_INFO("SPI %d generated for peer %s", response->params().spi(), peer.c_str());

	if (request->has_reverse_params()) {
		struct psp_gw_host remote_host = {};

		inet_pton(AF_INET, request->virt_src_ip().c_str(), &remote_host.vip);
		// remote_host.svc_ip not used

		result = create_tunnel_flow(&remote_host, request->request_id(), request->reverse_params());
		if (result != DOCA_SUCCESS) {
			return ::grpc::Status(::grpc::UNKNOWN,
					      "Failed to create the return flow for request " +
						      std::to_string(request->request_id()));
		}
		DOCA_LOG_INFO("Created return flow on SPI %d to peer %s",
			      request->reverse_params().spi(),
			      peer.c_str());
	}

	return ::grpc::Status::OK;
}

doca_error_t PSP_GatewayImpl::generate_tunnel_params(psp_gateway::TunnelParameters *params)
{
	doca_error_t result;

	auto *bulk_key_gen = this->get_bulk_key_gen();
	if (!bulk_key_gen) {
		DOCA_LOG_ERR("Failed to allocate bulk-key-gen object");
		return DOCA_ERROR_NO_MEMORY;
	}

	result = doca_flow_crypto_psp_spi_key_bulk_generate(bulk_key_gen);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to generate keys and SPIs: %s", doca_error_get_descr(result));
		return DOCA_ERROR_IO_FAILED;
	}

	uint32_t spi = 0;
	uint32_t key[key_len_words] = {}; // key is copied here from bulk
	result = doca_flow_crypto_psp_spi_key_bulk_get(bulk_key_gen, 0, &spi, key);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to retrieve SPI/Key: %s", doca_error_get_descr(result));
		return DOCA_ERROR_IO_FAILED;
	}

	params->set_mac_addr(pf->src_mac_str);
	params->set_ip_addr(pf->src_pip_str);
	params->set_psp_version(SUPPORTED_PSP_VER);
	params->set_spi(spi);
	params->set_encryption_key(key, key_len_bytes);
	params->set_virt_cookie(0x778899aabbccddee);

	debug_key(key, key_len_bytes);

	return DOCA_SUCCESS;
}

size_t PSP_GatewayImpl::try_connect(std::vector<psp_gw_host> &hosts)
{
	size_t num_connected = 0;
	for (auto host_iter = hosts.begin(); host_iter != hosts.end(); /* increment below */) {
		doca_error_t result = request_tunnel_to_host(&*host_iter, 0x0, true);
		if (result == DOCA_SUCCESS) {
			++num_connected;
			host_iter = hosts.erase(host_iter);
		} else {
			++host_iter;
		}
	}
	return num_connected;
}

psp_gw_host *PSP_GatewayImpl::lookup_remote_host(rte_be32_t dst_vip)
{
	for (auto &host : config->net_config.hosts) {
		if (host.vip == dst_vip) {
			return &host;
		}
	}
	return nullptr;
}

doca_error_t PSP_GatewayImpl::show_flow_counts(void)
{
	for (auto &session : sessions) {
		psp_flows->show_session_flow_count(session.first, session.second);
	}
	return DOCA_SUCCESS;
}

uint32_t PSP_GatewayImpl::next_crypto_id(void)
{
	if (next_crypto_id_ > config->max_tunnels) {
		return UINT32_MAX;
	}
	return next_crypto_id_++;
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

struct doca_flow_crypto_psp_spi_key_bulk *PSP_GatewayImpl::get_bulk_key_gen(void)
{
	if (!bulk_key_gen_) {
		doca_error_t result = doca_flow_crypto_psp_spi_key_bulk_alloc(pf->port_obj,
									      DOCA_FLOW_CRYPTO_KEY_256,
									      1,
									      &bulk_key_gen_);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate bulk-key-gen object: %s", doca_error_get_descr(result));
		}
	}
	return bulk_key_gen_;
}

void PSP_GatewayImpl::debug_key(const void *key, size_t key_size_bytes) const
{
	if (!DEBUG_KEYS) {
		return;
	}

	char key_str[key_size_bytes * 3];
	const uint8_t *key_bytes = (const uint8_t *)key;
	for (size_t i = 0, j = 0; i < key_size_bytes; i++) {
		j += sprintf(key_str + j, "%02X", key_bytes[i]);
		if ((i % 4) == 3) {
			j += sprintf(key_str + j, " ");
		}
	}
	DOCA_LOG_INFO("Associated encryption key: %s", key_str);
}
