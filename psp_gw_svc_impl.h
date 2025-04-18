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

#ifndef _PSP_GW_SVC_H
#define _PSP_GW_SVC_H

#include <memory>
#include <map>

#include <doca_flow.h>

#include <psp_gateway.pb.h>
#include <psp_gateway.grpc.pb.h>
#include "psp_gw_config.h"
#include "psp_gw_flows.h"

struct psp_pf_dev;
struct doca_flow_crypto_psp_spi_key_bulk;

/**
 * @brief Implementation of the PSP_Gateway service.
 *
 * Manages the generation of PSP encryption keys, which
 * are supplied to a remote service to establish a tunnel
 * connection.
 *
 * As a server, listens to requests for new tunnels, generates
 * parameters for the requestor to send encrypted packets, and
 * creates the flows required to send encrypted packets back
 * to the requestor.
 *
 * As a client, generates parameters for a remote service to
 * send encrypted packets, and sends them as part of the request.
 */
class PSP_GatewayImpl : public psp_gateway::PSP_Gateway::Service {
public:
	static constexpr uint16_t DEFAULT_HTTP_PORT_NUM = 3000;

	/**
	 * @brief Constructs the object. This operation cannot fail.
	 *
	 * @param [in] psp_flows The object which manages the doca resources.
	 */
	PSP_GatewayImpl(psp_gw_app_config *config);

	/**
	 * @brief Destroys the object.
	 */
	~PSP_GatewayImpl();

	/**
	 * @brief Returns a gRPC client for a given remote host
	 * Note: this assumes only a single PSP app instance per remote host
	 *
	 * @return: the gRPC stub associated with the given address
	 */
	::psp_gateway::PSP_Gateway::Stub *get_stub(const std::string &remote_host_ip);

	/**
	 * @brief Requests that the recipient allocate multiple SPIs and encryption keys
	 * so that the initiator can begin sending encrypted traffic.
	 *
	 * @context [in]: grpc context
	 * @request [in]: request parameters
	 * @response [out]: requested outputs
	 * @return: Indicates success/failure of the request
	 */
	::grpc::Status RequestMultipleTunnelParams(::grpc::ServerContext *context,
						   const ::psp_gateway::MultiTunnelRequest *request,
						   ::psp_gateway::MultiTunnelResponse *response) override;

	/**
	 * @brief Requests that the recipient rotate the PSP master key.
	 *
	 * @context [in]: grpc context
	 * @request [in]: request parameters
	 * @response [out]: requested outputs
	 * @return: Indicates success/failure of the request
	 */
	::grpc::Status RequestKeyRotation(::grpc::ServerContext *context,
					  const ::psp_gateway::KeyRotationRequest *request,
					  ::psp_gateway::KeyRotationResponse *response) override;

	/**
	 * @brief Indicates that this Service should attempt to replace any
	 * currently running instances.
	 *
	 * @context [in]: grpc context
	 * @request [in]: request parameters
	 * @response [out]: requested outputs
	 * @return: Indicates success/failure of the request
	 */
	::grpc::Status SetOpState(::grpc::ServerContext *context,
				  const ::psp_gateway::OpStateMsg *request,
				  ::psp_gateway::OpStateMsg *response) override;

	/**
	 * @brief Checks whether this Service takes precedence over all
	 * other instances.
	 *
	 * @context [in]: grpc context
	 * @request [in]: request parameters (ignored)
	 * @response [out]: requested outputs
	 * @return: Indicates success/failure of the request
	 */
	::grpc::Status GetOpState(::grpc::ServerContext *context,
				const ::psp_gateway::OpStateMsg *request,
				::psp_gateway::OpStateMsg *response) override;

	/**
	 * @brief Handles any "miss" packets received by RSS which indicate
	 *        a new tunnel connection is needed.
	 *
	 * @packet [in]: The packet received from RSS
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t handle_miss_packet(struct rte_mbuf *packet);

	/**
	 * @brief Displays the counters of all tunnel sessions that have
	 *        changed since the previous invocation.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t show_flow_counts(void);

	/**
	 * @brief Attempt to establish tunnels to each of the passed hosts.
	 * On success, a given host is removed from the list so that this
	 * method can be called repeatedly with the same list.
	 *
	 * @hosts [in/out]: the list of tunnels to try to establish
	 * @local_vf_addrs [in]: the IP address of the local VF netdev
	 * @return: the number of hosts successfully connected and removed from 'hosts'
	 */
	size_t try_connect(std::vector<psp_gw_nic_desc_t> &hosts, rte_be32_t local_vf_addr);

	doca_error_t init_devs();
	doca_error_t init_flows();
	doca_error_t init_doca_flow();

	void launch_lcores(volatile bool *force_quit);
	void lcore_callback();
	void kill_lcores();

private:

	psp_gw_nic_desc_t *lookup_nic(std::string vip);
	PSP_GatewayFlows* lookup_flows(std::string local_vip);

	doca_error_t request_tunnels_to_host(const std::vector<psp_session_desc_t> &session_desc);

	/**
	 * @brief Callback which is invoked to check the status of every entry
	 *        added to a flow pipe. See doca_flow_entry_process_cb.
	 *
	 * @entry [in]: The entry which was added/removed/updated
	 * @pipe_queue [in]: The index of the associated queue
	 * @status [in]: The result of the operation
	 * @op [in]: The type of the operation
	 * @user_ctx [in]: The argument supplied to add_entry, etc.
	 */
	static void check_for_valid_entry(doca_flow_pipe_entry *entry,
		uint16_t pipe_queue,
		enum doca_flow_entry_status status,
		enum doca_flow_entry_op op,
		void *user_ctx);

	void fill_tunnel_params(
		uint32_t *key,
		uint32_t spi,
		std::string local_pip,
		psp_gateway::TunnelParameters *params);

	// Application state data:
	psp_gw_app_config *config{};

	// mapping of public IP to flows, used for flow lookup
	using FlowNicPair = std::pair<std::string, PSP_GatewayFlows*>;
	std::vector<FlowNicPair> psp_flows;

	// Used to uniquely populate the request ID in each NewTunnelRequest message.
	uint64_t next_request_id{};

	// map each svc_ip to an RPC object
	std::map<std::string, std::shared_ptr<::psp_gateway::PSP_Gateway::Stub>> stubs;

	std::vector<struct lcore_params> lcore_params_list;
};

#endif // _PSP_GW_SVC_H
