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
 * As a client, generates parameteres for a remote service to
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
	PSP_GatewayImpl(psp_gw_app_config *config, PSP_GatewayFlows *psp_flows);

	/**
	 * @brief Requests that the recipient allocate a new SPI and encryption key
	 * so that the initiator can begin sending encrypted traffic.
	 *
	 * @context [in]: grpc context
	 * @request [in]: request parameters
	 * @response [out]: requested outputs
	 * @return: Indicates success/failure of the request
	 */
	::grpc::Status RequestTunnelParams(::grpc::ServerContext *context,
					   const ::psp_gateway::NewTunnelRequest *request,
					   ::psp_gateway::NewTunnelResponse *response) override;

	::grpc::Status UpdateTunnelParams(::grpc::ServerContext *context,
					   const ::psp_gateway::UpdateTunnelRequest *request,
					   ::psp_gateway::UpdateTunnelResponse *response) override;

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
	 * @brief Handles any "miss" packets recieved by RSS which indicate
	 *        a new tunnel connection is needed.
	 *
	 * @packet [in]: The packet received from RSS
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t handle_miss_packet(struct rte_mbuf *packet);

	/**
	 * @brief Sends a push update to all current sessions. If any of the updates fail,
	 * 	  fail immediately.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t update_current_sessions(void);

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
	size_t try_connect(std::vector<psp_gw_host> &hosts, rte_be32_t local_vf_addr);

private:
	/**
	 * @brief Returns the number of bits of the key size as determined
	 * by the given PSP protocol version.
	 *
	 * @psp_proto_ver [in]: the PSP protocol version
	 * @return: 128 or 256 depending on the key type
	 */
	static uint32_t psp_version_to_key_length_bits(uint32_t psp_proto_ver)
	{
		return (psp_proto_ver == 0 || psp_proto_ver == 2) ? 128 : 256;
	}

	/**
	 * @brief Sends a request to the given remote host
	 * The request includes the parameters required for
	 * traffic in the reverse direction (remote to local).
	 * An ACL is also provided for return traffic, if the
	 * local/remote virtual addresses are provided.
	 *
	 * @remote_host [in]: The remote host to which we will create a tunnel
	 * @local_virt_ip [in]: The destination virtual IP address for the return traffic
	 * @supply_reverse_params [in]: Whether to include tunnel parameters for traffic
	 * returning to the sender of the request.
	 * @suppress_failure_msg [in]: Indicates we are okay with a failure to connect, such
	 * as during application startup.
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t request_tunnel_to_host(struct psp_gw_host *remote_host,
					    doca_be32_t local_virt_ip,
					    bool supply_reverse_params,
					    bool suppress_failure_msg);

	/**
	 * @brief Creates the flow entries for a given session
	 *
	 * @remote_host [in]: the remote host for which flow rules will be created
	 * @request_id [in]: the request to log in case of error
	 * @params [in]: the crypto/encap parameteres received from gRPC
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t create_tunnel_flow(const struct psp_gw_host *remote_host,
					uint64_t request_id,
					const psp_gateway::TunnelParameters &params);

	/**
	 * @brief Returns a gRPC client for a given remote host
	 * Note: this assumes only a single PSP app instance per remote host
	 *
	 * @return: the gRPC stub associated with the given address
	 */
	::psp_gateway::PSP_Gateway::Stub *get_stub(const std::string &remote_host_ip);

	/**
	 * @brief Checks whether a remote host has been configured to receive
	 * traffic to the given destination virtual IP address
	 *
	 * @dst_vip [in]: the desired destination IP address
	 * @return: the remote gateway host, if one exists
	 */
	psp_gw_host *lookup_remote_host(rte_be32_t dst_vip);

	/**
	 * @brief Checks the list of supported versions in the request
	 *
	 * @request [in]: The request received over gRPC
	 * @return: the supported version number, or -1 if no acceptable
	 * version was requested.
	 */
	int select_psp_version(const ::psp_gateway::NewTunnelRequest *request) const;

	/**
	 * @brief Checks whether the given PSP version is supported
	 *
	 * @psp_ver [in]: The requested PSP protocol version
	 * @return: True if the version is supported; false otherwise
	 */
	bool is_psp_ver_supported(uint32_t psp_ver) const
	{
		return SUPPORTED_PSP_VERSIONS.count(psp_ver) > 0;
	}

	/**
	 * @brief Generates a new SPI/key pair and writes the new SPI/Key
	 * and all required PF attributes to a gRPC request object.
	 *
	 * @psp_ver [in]: The PSP version (key length) to use for the session
	 * @params [in/out]: The gRPC request object to populate
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t generate_tunnel_params(int psp_ver, psp_gateway::TunnelParameters *params);

	/**
	 * @brief Allocates the spi/key bulk generator, if it does not exist yet
	 *
	 * @key_size_bits [in]: 128 or 256
	 * @return: The allocated bulk generator
	 */
	struct doca_flow_crypto_psp_spi_key_bulk *get_bulk_key_gen(uint32_t key_size_bits);

	/**
	 * @brief Dumps the hex bytes of the given PSP key
	 *
	 * @msg_prefix [in]: Prepend this string to the key log
	 * @key [in]: the bytes of the key object
	 * @key_size [in]: indicates whether the key is 128 or 256 bits
	 */
	void debug_key(const char *msg_prefix, const void *key, size_t key_size_bytes) const;

	/**
	 * @brief Determines the next available crypto_id at which to store the
	 * next PSP encryption key
	 *
	 * @return: The crypto_id to use for the PSP shared resource
	 */
	uint32_t allocate_crypto_id(void);

	/**
	 * @brief Releases the given crypto_id so that it can be reused
	 *
	 * @crypto_id [in]: The crypto_id to release
	 */
	void release_crypto_id(uint32_t crypto_id);

	// Application state data:

	psp_gw_app_config *config{};

	PSP_GatewayFlows *psp_flows{};

	psp_pf_dev *pf{};

	doca_flow_crypto_psp_spi_key_bulk *bulk_key_gen_128{};
	doca_flow_crypto_psp_spi_key_bulk *bulk_key_gen_256{};

	// Used to uniquely populate the request ID in each NewTunnelRequest message.
	uint64_t next_request_id{};

	// This flag will cause encryption keys to be logged to stderr, etc.
	const bool DEBUG_KEYS{false};

	// map each svc_ip to an RPC object
	std::map<std::string, std::unique_ptr<::psp_gateway::PSP_Gateway::Stub>> stubs;

	// map each dst vip to an active session object
	std::map<std::string, psp_session_t> sessions;

	// Used to assign a unique shared-resource ID to each encryption flow.
	std::set<uint32_t> available_crypto_ids;

};

#endif // _PSP_GW_SVC_H
