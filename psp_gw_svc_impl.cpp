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

bool enable_reverse_params = false;
bool enable_crypto_id_recycling = true;
bool enable_key_rotation = false;

PSP_GatewayImpl::PSP_GatewayImpl(psp_gw_app_config *config, PSP_GatewayFlows *psp_flows)
	: config(config),
	  psp_flows(psp_flows),
	  pf(psp_flows->pf()),
	  DEBUG_KEYS(config->debug_keys)
{
	for (uint32_t i = 1; i <= (config->max_tunnels + 1); ++i) {
		available_crypto_ids.insert(i);
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

		doca_error_t result =
			request_tunnel_to_host(remote_host, ipv4_hdr->src_addr /* local addr */, true, false);
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

doca_error_t PSP_GatewayImpl::update_current_sessions()
{
	DOCA_LOG_DBG("Updating current sessions");

	for (auto &session : sessions) {
		psp_session_t *psp_session = &session.second;
		psp_gw_host *remote_host = lookup_remote_host(psp_session->dst_vip);
		if (remote_host == NULL) {
			DOCA_LOG_ERR("Failed to find remote host for session %s",
				     ipv4_to_string(psp_session->dst_vip).c_str());
			return DOCA_ERROR_NOT_FOUND;
		}
#if 0
		doca_error_t result = request_tunnel_to_host(remote_host, config->local_vf_addr_raw, true, true);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to update session %s", ipv4_to_string(psp_session->dst_vip).c_str());
			return result;
		}
#else
		std::string remote_host_svc_pip = ipv4_to_string(remote_host->svc_ip);
		auto *stub = get_stub(remote_host_svc_pip);

		::grpc::ClientContext context;
		::psp_gateway::UpdateTunnelRequest request;
		::psp_gateway::UpdateTunnelResponse response;
		request.set_request_id(++next_request_id);
		// Note the src/dst are reversed from RequestTunnelParams()
		request.set_virt_src_ip(ipv4_to_string(config->local_vf_addr_raw));
		request.set_virt_dst_ip(ipv4_to_string(psp_session->src_vip));
		doca_error_t result =
			generate_tunnel_params((int)config->net_config.default_psp_proto_ver, request.mutable_params());
		if (result != DOCA_SUCCESS) {
			continue;
		}
		DOCA_LOG_INFO("Re-generated SPI/Key for %s: new SPI 0x%x", request.virt_src_ip().c_str(), request.params().spi());

		::grpc::Status status = stub->UpdateTunnelParams(&context, request, &response);
		if (!status.ok()) {
			DOCA_LOG_ERR("Request for new SPI/Key to remote host %s failed: %s",
				     remote_host_svc_pip.c_str(),
				     status.error_message().c_str());
			continue;
		}

		if (!config->disable_ingress_acl) {
			psp_session->spi_ingress = request.params().spi();

			// Note the old session.acl_entry should be freed later
			result = psp_flows->add_ingress_acl_entry(psp_session);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failed to open ACL from %s on SPI 0x%x: %s",
					     request.virt_src_ip().c_str(),
					     psp_session->spi_ingress,
					     doca_error_get_descr(result));
				return result;
			}

			DOCA_LOG_INFO("Opened ACL from host %s on SPI 0x%x",
				      request.virt_src_ip().c_str(),
				      psp_session->spi_ingress);
		}
#endif
	}
	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayImpl::request_tunnel_to_host(struct psp_gw_host *remote_host,
						     doca_be32_t local_virt_ip,
						     bool supply_reverse_params,
						     bool suppress_failure_msg)
{
	std::string remote_host_svc_pip = ipv4_to_string(remote_host->svc_ip);
	std::string remote_host_vip = ipv4_to_string(remote_host->vip);
	std::string local_vip = ipv4_to_string(local_virt_ip);

	auto *stub = get_stub(remote_host_svc_pip);

	::grpc::ClientContext context;
	::psp_gateway::NewTunnelRequest request;
	request.set_request_id(++next_request_id);
	request.add_psp_versions_accepted(config->net_config.default_psp_proto_ver);
	request.set_virt_src_ip(local_vip);
	request.set_virt_dst_ip(remote_host_vip);

	// Save a round-trip, if a local virtual IP was given.
	// Otherwise, expect the remote host to send a separate request.
	if (enable_reverse_params && supply_reverse_params) {
		if (!local_virt_ip) {
			DOCA_LOG_ERR("Cannot create reverse params without a local virt ip addr");
			return DOCA_ERROR_INVALID_VALUE;
		}

		doca_error_t result = generate_tunnel_params((int)config->net_config.default_psp_proto_ver,
							     request.mutable_reverse_params());
		if (result != DOCA_SUCCESS) {
			return result;
		}

		if (!config->disable_ingress_acl) {
			auto &session = sessions[remote_host_vip];
			session.spi_ingress = request.reverse_params().spi();
			session.src_vip = remote_host->vip;
			session.pkt_count_ingress = UINT64_MAX;

			result = psp_flows->add_ingress_acl_entry(&session);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failed to open ACL from %s on SPI 0x%x: %s",
					     remote_host_vip.c_str(),
					     session.spi_ingress,
					     doca_error_get_descr(result));
				return result;
			}

			DOCA_LOG_INFO("Opened ACL from host %s on SPI 0x%x",
				      remote_host_vip.c_str(),
				      session.spi_ingress);
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
	doca_error_t result = DOCA_SUCCESS;
	std::string remote_host_svc_ip = ipv4_to_string(remote_host->svc_ip);
	std::string remote_host_vip = ipv4_to_string(remote_host->vip);

	if (!is_psp_ver_supported(params.psp_version())) {
		DOCA_LOG_ERR("Request for unsupported PSP version %d", params.psp_version());
		return DOCA_ERROR_UNSUPPORTED_VERSION;
	}

	uint32_t key_len_bytes = psp_version_to_key_length_bits(params.psp_version()) / 8;

	if (params.encryption_key().size() != key_len_bytes) {
		DOCA_LOG_ERR("Request for new SPI/Key to remote host %s failed: %s (%ld)",
			     remote_host_svc_ip.c_str(),
			     "Invalid encryption key length",
			     params.encryption_key().size() * 8);
		return DOCA_ERROR_IO_FAILED;
	}

	uint32_t crypto_id = allocate_crypto_id();
	if (crypto_id == UINT32_MAX) {
		DOCA_LOG_ERR("Exhausted available crypto_ids; cannot complete new tunnel");
		return DOCA_ERROR_NO_MEMORY;
	}

	const void *encrypt_key = params.encryption_key().c_str();
	DOCA_LOG_INFO("Received tunnel params from %s, SPI 0x%x", remote_host_svc_ip.c_str(), params.spi());
	debug_key("Received", encrypt_key, params.encryption_key().size());

	std::string bad_key = params.encryption_key();
	for (uint32_t i=0; i<key_len_bytes; i++)
		bad_key.at(i) ^= 1;

	// If there is an existing session, we should update it instead of making a new one
	auto existing_session = sessions.find(remote_host_vip);
	if (existing_session != sessions.end() && existing_session->second.encap_encrypt_entry) {
		DOCA_LOG_WARN("Session already exists for remote host %s. Updating it.", remote_host_vip.c_str());
		psp_session_t new_session = existing_session->second; // copy
		new_session.crypto_id = crypto_id;
		new_session.spi_egress = params.spi();

		result = psp_flows->update_encrypt_entry(&new_session, encrypt_key);
		if (result != DOCA_SUCCESS) {
			release_crypto_id(crypto_id);
			return result;
		}

		release_crypto_id(existing_session->second.crypto_id);
		existing_session->second = new_session;
		return DOCA_SUCCESS;
	}

	auto &session = sessions[remote_host_vip];
	session.dst_vip = remote_host->vip;
	session.spi_egress = params.spi();
	session.crypto_id = crypto_id;
	session.psp_proto_ver = params.psp_version();
	session.vc = params.virt_cookie();

	if (rte_ether_unformat_addr(params.mac_addr().c_str(), &session.dst_mac)) {
		DOCA_LOG_ERR("Failed to convert mac addr: %s", params.mac_addr().c_str());
		sessions.erase(remote_host_vip);
		release_crypto_id(crypto_id);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (inet_pton(AF_INET6, params.ip_addr().c_str(), session.dst_pip) != 1) {
		DOCA_LOG_ERR("Failed to parse dst_pip %s", params.ip_addr().c_str());
		sessions.erase(remote_host_vip);
		release_crypto_id(crypto_id);
		return DOCA_ERROR_INVALID_VALUE;
	}

	result = psp_flows->add_encrypt_entry(&session, bad_key.data());
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create session from %s request %ld: %s",
			     remote_host_svc_ip.c_str(),
			     request_id,
			     doca_error_get_descr(result));
		release_crypto_id(crypto_id);
		sessions.erase(remote_host_vip);
		return result;
	}

	uint32_t old_crypto_id = session.crypto_id;
	crypto_id = allocate_crypto_id();
	if (crypto_id == UINT32_MAX) {
		DOCA_LOG_ERR("Exhausted available crypto_ids; cannot complete new tunnel");
		return DOCA_ERROR_NO_MEMORY;
	}

	session.crypto_id = crypto_id;
	result = psp_flows->update_encrypt_entry(&session, bad_key.data());
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to re-create session from %s request %ld: %s",
			     remote_host_svc_ip.c_str(),
			     request_id,
			     doca_error_get_descr(result));
		release_crypto_id(crypto_id);
		sessions.erase(remote_host_vip);
		return result;
	}

	release_crypto_id(old_crypto_id);

	old_crypto_id = session.crypto_id;
	crypto_id = allocate_crypto_id();
	if (crypto_id == UINT32_MAX) {
		DOCA_LOG_ERR("Exhausted available crypto_ids; cannot complete new tunnel");
		return DOCA_ERROR_NO_MEMORY;
	}

	session.crypto_id = crypto_id;
	result = psp_flows->update_encrypt_entry(&session, encrypt_key);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to re-create session from %s request %ld: %s",
			     remote_host_svc_ip.c_str(),
			     request_id,
			     doca_error_get_descr(result));
		release_crypto_id(crypto_id);
		sessions.erase(remote_host_vip);
		return result;
	}

	release_crypto_id(old_crypto_id);

	return DOCA_SUCCESS;
}

int PSP_GatewayImpl::select_psp_version(const ::psp_gateway::NewTunnelRequest *request) const
{
	for (int ver : request->psp_versions_accepted()) {
		if (is_psp_ver_supported(ver) > 0)
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

	int psp_ver = select_psp_version(request);
	if (psp_ver < 0) {
		std::string supported_psp_versions = "[ ";
		for (auto psp_ver : SUPPORTED_PSP_VERSIONS) {
			supported_psp_versions += std::to_string(psp_ver) + " ";
		}
		supported_psp_versions += "]";
		std::string error_str = "Rejecting tunnel request from peer " + peer + ", PSP verison must be one of " +
					supported_psp_versions;
		DOCA_LOG_ERR("%s", error_str.c_str());
		return ::grpc::Status(::grpc::INVALID_ARGUMENT, error_str);
	}

	result = generate_tunnel_params(psp_ver, response->mutable_params());
	if (result != DOCA_SUCCESS) {
		return ::grpc::Status(::grpc::RESOURCE_EXHAUSTED, "Failed to generate SPI/Key");
	}

	DOCA_LOG_INFO("SPI 0x%x generated for addr %s on peer %s",
		      response->params().spi(),
		      request->virt_src_ip().c_str(),
		      peer.c_str());

	if (!config->disable_ingress_acl) {
		auto &session = sessions[request->virt_src_ip()];
		session.spi_ingress = response->params().spi();
		if (inet_pton(AF_INET, request->virt_src_ip().c_str(), &session.src_vip) != 1) {
			return ::grpc::Status(grpc::INVALID_ARGUMENT,
					      "Failed to parse virt_src_ip: " + request->virt_src_ip());
		}
		session.pkt_count_ingress = UINT64_MAX;

		result = psp_flows->add_ingress_acl_entry(&session);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to open ACL from %s on SPI 0x%x: %s",
				     request->virt_src_ip().c_str(),
				     session.spi_ingress,
				     doca_error_get_descr(result));
			return ::grpc::Status(grpc::INTERNAL, "Failed to create ingress ACL session flow");
		}

		DOCA_LOG_INFO("Opened ACL from host %s on SPI 0x%x",
			      request->virt_src_ip().c_str(),
			      session.spi_ingress);
	}

	if (request->has_reverse_params()) {
		struct psp_gw_host remote_host = {};

		if (inet_pton(AF_INET, request->virt_src_ip().c_str(), &remote_host.vip) != 1) {
			return ::grpc::Status(grpc::INVALID_ARGUMENT,
					      "Failed to parse virt_src_ip: " + request->virt_src_ip());
		}
		// remote_host.svc_ip not used

		result = create_tunnel_flow(&remote_host, request->request_id(), request->reverse_params());
		if (result != DOCA_SUCCESS) {
			return ::grpc::Status(::grpc::UNKNOWN,
					      "Failed to create the return flow for request " +
						      std::to_string(request->request_id()));
		}
		DOCA_LOG_INFO("Created return flow on SPI 0x%x to peer %s",
			      request->reverse_params().spi(),
			      peer.c_str());
	}

	return ::grpc::Status::OK;
}

doca_error_t PSP_GatewayImpl::generate_tunnel_params(int psp_ver, psp_gateway::TunnelParameters *params)
{
	doca_error_t result;

	uint32_t key_len_bits = psp_version_to_key_length_bits(psp_ver);
	auto *bulk_key_gen = this->get_bulk_key_gen(key_len_bits);
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
	uint32_t key_len_words = key_len_bits / 32;
	uint32_t key[key_len_words] = {}; // key is copied here from bulk
	result = doca_flow_crypto_psp_spi_key_bulk_get(bulk_key_gen, 0, &spi, key);
	doca_flow_crypto_psp_spi_key_wipe(bulk_key_gen, 0);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to retrieve SPI/Key: %s", doca_error_get_descr(result));
		return DOCA_ERROR_IO_FAILED;
	}

	uint32_t key_len_bytes = key_len_bits / 8;
	params->set_mac_addr(pf->src_mac_str);
	params->set_ip_addr(pf->src_pip_str);
	params->set_psp_version(psp_ver);
	params->set_spi(spi);
	params->set_encryption_key(key, key_len_bytes);
	params->set_virt_cookie(0x778899aabbccddee);

	debug_key("Generated", key, key_len_bytes);

	return DOCA_SUCCESS;
}

::grpc::Status PSP_GatewayImpl::UpdateTunnelParams(::grpc::ServerContext *context,
						   const ::psp_gateway::UpdateTunnelRequest *request,
						   ::psp_gateway::UpdateTunnelResponse *response)
{
	std::string remote_host_svc_ip = context ? context->peer() : "[TESTING]";
	std::string local_vip = request->virt_dst_ip();
	std::string remote_vip = request->virt_src_ip();

	// If there is an existing session, we should update it instead of making a new one
	auto existing_session = sessions.find(remote_vip);
	if (existing_session == sessions.end() || !existing_session->second.encap_encrypt_entry) {
		DOCA_LOG_WARN("UpdateTunnelParams: Session not found for remote host %s (%s->%s).",
			      remote_host_svc_ip.c_str(),
			      remote_vip.c_str(),
			      local_vip.c_str());
		return ::grpc::Status(::grpc::INVALID_ARGUMENT, "Unknown virt_src_ip");
	}

	doca_error_t result = DOCA_SUCCESS;

	auto &params = request->params();
	if (!is_psp_ver_supported(params.psp_version())) {
		DOCA_LOG_ERR("Request for unsupported PSP version %d", params.psp_version());
		return ::grpc::Status(::grpc::INVALID_ARGUMENT, "Invalid PSP version");
	}

	uint32_t key_len_bytes = psp_version_to_key_length_bits(params.psp_version()) / 8;

	if (params.encryption_key().size() != key_len_bytes) {
		DOCA_LOG_ERR("Request for new SPI/Key to remote host %s failed: %s (%ld)",
			     remote_host_svc_ip.c_str(),
			     "Invalid encryption key length",
			     params.encryption_key().size() * 8);
		return ::grpc::Status(::grpc::INVALID_ARGUMENT, "Invalid key size");
	}

	uint32_t crypto_id = allocate_crypto_id();
	if (crypto_id == UINT32_MAX) {
		DOCA_LOG_ERR("Exhausted available crypto_ids; cannot complete new tunnel");
		return ::grpc::Status(::grpc::RESOURCE_EXHAUSTED,
				      "Exhausted available crypto_ids; cannot complete new tunnel");
	}

	const void *encrypt_key = params.encryption_key().c_str();
	DOCA_LOG_INFO("Received tunnel params from %s, SPI 0x%x", remote_host_svc_ip.c_str(), params.spi());
	debug_key("Received", encrypt_key, params.encryption_key().size());

	psp_session_t new_session = existing_session->second; // copy
	new_session.crypto_id = crypto_id;
	new_session.spi_egress = params.spi();

	result = psp_flows->update_encrypt_entry(&new_session, encrypt_key);
	if (result != DOCA_SUCCESS) {
		release_crypto_id(crypto_id);
		return ::grpc::Status(::grpc::INTERNAL, "Failed to update tunnel flow");
	}

	release_crypto_id(existing_session->second.crypto_id);
	existing_session->second = new_session;
	return ::grpc::Status::OK;
}

::grpc::Status PSP_GatewayImpl::RequestKeyRotation(::grpc::ServerContext *context,
						   const ::psp_gateway::KeyRotationRequest *request,
						   ::psp_gateway::KeyRotationResponse *response)
{
	doca_error_t result;

	(void)context;
	DOCA_LOG_INFO("Received PSP Master Key Rotation Request");

	response->set_request_id(request->request_id());

	if (enable_key_rotation) {
		result = doca_flow_crypto_psp_master_key_rotate(pf->port_obj);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_WARN("Key Rotation Failed: %s", doca_error_get_descr(result));
			return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "Key Rotation Failed");
		}
	}

	if (request->issue_new_keys()) {
		result = update_current_sessions();
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to update current sessions: %s", doca_error_get_descr(result));
			return ::grpc::Status(::grpc::StatusCode::UNKNOWN, "Failed to update current sessions");
		}
	}

	return ::grpc::Status::OK;
}

size_t PSP_GatewayImpl::try_connect(std::vector<psp_gw_host> &hosts, rte_be32_t local_vf_addr)
{
	size_t num_connected = 0;
	for (auto host_iter = hosts.begin(); host_iter != hosts.end(); /* increment below */) {
		doca_error_t result = request_tunnel_to_host(&*host_iter, local_vf_addr, false, true);
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

uint32_t PSP_GatewayImpl::allocate_crypto_id(void)
{
	if (available_crypto_ids.empty()) {
		DOCA_LOG_WARN("Exhausted available crypto_ids");
		return UINT32_MAX;
	}

	auto crypto_id_it = available_crypto_ids.begin();
	uint32_t crypto_id = *crypto_id_it;
	available_crypto_ids.erase(crypto_id);
	DOCA_LOG_DBG("Allocated crypto_id %d", crypto_id);
	return crypto_id;
}

void PSP_GatewayImpl::release_crypto_id(uint32_t crypto_id)
{
	if (!enable_crypto_id_recycling) return;

	if (available_crypto_ids.find(crypto_id) != available_crypto_ids.end()) {
		DOCA_LOG_WARN("Crypto ID %d already released", crypto_id);
	}
	DOCA_LOG_DBG("Released crypto_id %d", crypto_id);
	available_crypto_ids.insert(crypto_id);
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

struct doca_flow_crypto_psp_spi_key_bulk *PSP_GatewayImpl::get_bulk_key_gen(uint32_t key_size_bits)
{
	auto &key_gen = key_size_bits == 128 ? bulk_key_gen_128 : bulk_key_gen_256;
	if (!key_gen) {
		auto key_type = key_size_bits == 128 ? DOCA_FLOW_CRYPTO_KEY_128 : DOCA_FLOW_CRYPTO_KEY_256;
		doca_error_t result = doca_flow_crypto_psp_spi_key_bulk_alloc(pf->port_obj, key_type, 1, &key_gen);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to allocate bulk-key-gen object: %s", doca_error_get_descr(result));
		}
	}
	return key_gen;
}

void PSP_GatewayImpl::debug_key(const char *msg_prefix, const void *key, size_t key_size_bytes) const
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
	DOCA_LOG_INFO("%s encryption key: %s", msg_prefix, key_str);
}
