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

#ifndef FLOWS_H_
#define FLOWS_H_

#include <netinet/in.h>
#include <rte_ether.h>
#include <string>
#include <unordered_map>

#include <doca_flow.h>
#include <doca_dev.h>

#include "psp_gw_config.h"

static const int NUM_OF_PSP_SYNDROMES = 4; // None, ICV Fail, Bad Trailer

struct psp_gw_app_config;

/**
 * @brief user context struct that will be used in entries process callback
 */
struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

/**
 * @brief Maintains the state of the host PF
 */
struct psp_pf_dev {
	struct doca_dev *dev;

	uint16_t pf_port_id;
	struct doca_flow_port *pf_port;
	struct rte_ether_addr pf_mac;
	std::string pf_mac_str;

	uint16_t vf_port_id;
	struct doca_flow_port *vf_port;
	struct rte_ether_addr vf_mac;
	std::string vf_mac_str;

	struct doca_flow_ip_addr local_pip; // Physical/Outer IP addr
	std::string local_pip_str;

};

struct psp_session_desc_t {
	std::string local_vip;
	std::string remote_vip;
	std::string remote_pip;
};

struct psp_session_desc_hash {
    size_t operator()(const psp_session_desc_t& session) const {
        return std::hash<std::string>()(session.local_vip + session.remote_vip + session.remote_pip);
    }
};

struct psp_session_desc_eq {
    bool operator()(const psp_session_desc_t& lhs, const psp_session_desc_t& rhs) const {
        return lhs.local_vip == rhs.local_vip &&
			   lhs.remote_vip == rhs.remote_vip &&
		       lhs.remote_pip == rhs.remote_pip;
    }
};

/**
 * @brief describes a PSP tunnel connection to a single address
 *        on a remote host
 */
struct psp_session_egress_t {
	uint32_t crypto_id;   //!< Internal shared-resource index

	doca_flow_pipe_entry *encap_encrypt_entry;
	uint64_t pkt_count_egress;
};

/**
 * @brief describes a PSP tunnel connection from a single address
 *        on a remote host
 */
struct psp_session_ingress_t {
	struct doca_flow_pipe_entry *ingress_acl_entry;
	struct doca_flow_pipe_entry *expiring_ingress_acl_entry;
	uint64_t pkt_count_ingress;
};


struct spi_keyptr_t {
	uint64_t spi;
	void *key;
};

struct spi_key_t {
	uint64_t spi;
	uint32_t key[8];
};

/**
 * @brief The entity which owns all the doca flow shared
 *        resources and flow pipes (but not sessions).
 */
class PSP_GatewayFlows {
public:
	/**
	 * @brief Constructs the object. This operation cannot fail.
	 * @param [in] nic_info The NIC information
	 * @param [in] app_config The application configuration
	 * @param [in] crypto_id_start The starting index for crypto IDs.
	 */
	PSP_GatewayFlows(psp_gw_nic_desc_t nic_info, psp_gw_app_config *app_config, uint32_t crypto_id_start);

	/**
	 * Deallocates all associated DOCA objects.
	 * In case of failure, an error is logged and progress continues.
	 */
	virtual ~PSP_GatewayFlows(void);

	/**
	 * @brief Probes the PF device and its representors.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t init_dev(void);

	/**
	 * @brief Initialized the DOCA resources.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t init_flows(void);

	/**
	 * @brief Rotate the master key.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t rotate_master_key(std::vector<psp_session_desc_t>& sessions_to_update);

	/**
	 * @brief Re-generate all current ingress paths with new SPIs and keys.
	 * @param [out] sessions The sessions which were successfully updated
	 * @param [out] spi_keys The SPIs and keys to use for each session. Invalid if
	 * 	  the return value is DOCA_ERROR.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> update_ingress_paths(
		const std::vector<psp_session_desc_t> &sessions,
		const std::vector<struct spi_key_t> &spi_keys
	);

	/**
	 * @brief Create new ingress paths.
	 * @param [in] sessions The sessions to update
	 * @param [out] spi_keys The SPIs and keys to use for each session. Invalid if
	 * 	  the return value is DOCA_ERROR.
	 *
	 * @return: vector of DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> create_ingress_paths(
		const std::vector<struct psp_session_desc_t> &sessions,
		std::vector<struct spi_key_t> &spi_keys
	);

	/**
	 * @brief Delete the indicated ingress paths.
	 * @param [in] sessions The sessions to delete
	 *
	 * @return: vector of DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> expire_ingress_paths(
		const std::vector<psp_session_desc_t> &sessions,
		const std::vector<bool> expire_old
	);

	/**
	 * @brief Set the egress path for sessions[i] to use spi[i] and key[i]
	 * @param [in] sessions The sessions to update
	 * @param [in] spi_keys The SPIs and keys to use for each session.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	std::vector<doca_error_t> set_egress_paths(
		const std::vector<psp_session_desc_t> &sessions,
		const std::vector<struct spi_keyptr_t> &spi_keys
	);

	/**
	 * @brief returns the NIC's public IP.
	 *
	 * @return: std::string with the NIC's public IP
	 */
	std::string get_pip(void) {
		return pf_dev.local_pip_str;
	}

	void show_static_flow_counts(void);
	void show_session_flow_counts(void);

private:

	/**
	 * @brief Starts the given port (with optional dev pointer) to create
	 *        a doca flow port.
	 *
	 * @port_id [in]: the numerical index of the port
	 * @port_dev [in]: the doca_dev returned from doca_dev_open()
	 * @port [out]: the resulting port object
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t start_port(uint16_t port_id, doca_dev *port_dev, doca_flow_port **port);

	/**
	 * @brief handles the binding of the shared resources to ports
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t bind_shared_resources(void);

	/**
	 * @brief wrapper for doca_flow_pipe_add_entry()
	 * Handles the call to process_entry and its callback for a single entry.
	 *
	 * @pipe_queue [in]: the queue index associated with the caller cpu core
	 * @pipe [in]: the pipe on which to add the entry
	 * @port [in]: the port which owns the pipe
	 * @match [in]: packet match criteria
	 * @actions [in]: packet mod actions
	 * @mon [in]: packet monitoring actions
	 * @fwd [in]: packet forwarding actions
	 * @entry [out]: the newly created flow entry
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t add_single_entry(uint16_t pipe_queue,
				      doca_flow_pipe *pipe,
				      doca_flow_port *port,
				      const doca_flow_match *match,
				      const doca_flow_actions *actions,
				      const doca_flow_monitor *mon,
				      const doca_flow_fwd *fwd,
				      doca_flow_pipe_entry **entry);

	/**
	 * Creates the entry point to the CPU Rx queues
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t rss_pipe_create(void);

	/**
	 * Creates the pipe which counts the various syndrome types
	 * and drops the packets
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t syndrome_stats_pipe_create(void);

	/**
	 * Top-level pipe creation method
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t create_pipes(void);

	/**
	 * @brief handles the setup of the packet mirroring shared resources
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t configure_mirrors(void);

	/**
	 * Creates the pipe to only accept incoming packets from
	 * appropriate sources.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_acl_pipe_create(void);

	/**
	 * Creates the pipe to sample packets with the PSP.S bit set
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_sampling_pipe_create(void);

	/**
	 * Creates the PSP decryption pipe.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_decrypt_pipe_create(void);

	/**
	 * @brief Creates a pipe to fwd packets to port
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t empty_pipe_create_not_sampled(void);

	/**
	 * Creates the pipe to mark and randomly sample outgoing packets
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t egress_sampling_pipe_create(void);

	/**
	 * Creates the pipe to trap outgoing packets to unregistered destinations
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t egress_acl_pipe_create(void);

	/**
	 * @brief Creates a pipe whose only purpose is to relay
	 * flows from the egress domain to the secure-egress domain,
	 * and to relay injected ARP responses back to the VF.
	 *
	 * @next_pipe [in]: The pipe to which the empty pipe
	 * should forward its traffic.
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t empty_pipe_create(doca_flow_pipe *next_pipe);

	/**
	 * @brief Creates the first pipe hit by packets arriving to
	 * the eswitch from either the uplink (wire) or the VF.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_root_pipe_create(void);

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

	/**
	 * @brief Generates a new SPI and key pair for use in a PSP session
	 *
	 * @key_len_bits [in]: The length of the key to generate
	 * @nr_keys_spis [in]: The number of keys and SPIs to generate
	 * @keys [out]: The generated keys
	 * @spis [out]: The generated SPIs
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t
	generate_keys_spis(uint32_t key_len_bits,
						 uint32_t nr_keys_spis,
						 uint32_t *keys,
						 uint32_t *spis);

	/**
	 * @brief Adds an ingress ACL entry for the given session to accept
	 *        the combination of src_vip and SPI.
	 *
	 * @session [in]: the session for which an ingress ACL flow should be created
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t add_ingress_acl_entry(const psp_session_desc_t &session, uint32_t spi, doca_flow_pipe_entry **entry);

	doca_error_t update_single_entry(uint16_t pipe_queue,
						doca_flow_pipe *pipe,
						const doca_flow_match *match,
						const doca_flow_actions *actions,
						const doca_flow_monitor *mon,
						const doca_flow_fwd *fwd,
						doca_flow_pipe_entry *entry);

	doca_error_t remove_single_entry(doca_flow_pipe_entry *entry);

	doca_error_t config_encrypt_entry(const psp_session_desc_t &session, uint32_t spi, uint32_t crypto_id, doca_flow_pipe_entry **new_entry);

	doca_error_t set_egress_path(const psp_session_desc_t &session, const spi_keyptr_t &spi_key);
	void format_encap_data_ipv6(const psp_session_desc_t &session, uint32_t spi, uint8_t *encap_data);

	struct pipe_query;
	std::pair<uint64_t, uint64_t> perform_pipe_query(pipe_query *query, bool suppress_output);

	bool sampling_enabled (void) {
		return app_config->log2_sample_rate > 0;
	}

	// Input during init
	psp_gw_app_config *app_config{};
	psp_gw_nic_desc_t nic_info;

	// Queried state during init
	psp_pf_dev pf_dev{};

	// Crypto ids bound to the device
	std::set<uint32_t> available_crypto_ids;

	// Tracking data relevant to each session
	std::unordered_map<psp_session_desc_t, psp_session_ingress_t, psp_session_desc_hash, psp_session_desc_eq> ingress_sessions;
	std::unordered_map<psp_session_desc_t, psp_session_egress_t, psp_session_desc_hash, psp_session_desc_eq> egress_sessions;

	// general pipes
	struct doca_flow_pipe *rss_pipe{};
	struct doca_flow_pipe *ingress_root_pipe{};

	// net-to-host pipes
	struct doca_flow_pipe *ingress_decrypt_pipe{};
	struct doca_flow_pipe *ingress_sampling_pipe{};
	struct doca_flow_pipe *ingress_acl_pipe{};

	// host-to-net pipes
	struct doca_flow_pipe *egress_acl_pipe{};
	struct doca_flow_pipe *egress_sampling_pipe{};
	struct doca_flow_pipe *egress_encrypt_pipe{};
	struct doca_flow_pipe *syndrome_stats_pipe{};
	struct doca_flow_pipe *empty_pipe{};
	struct doca_flow_pipe *empty_pipe_not_sampled{};

	// static pipe entries
	struct doca_flow_pipe_entry *default_rss_entry{};
	struct doca_flow_pipe_entry *default_decrypt_entry{};
	struct doca_flow_pipe_entry *default_ingr_sampling_entry{};
	struct doca_flow_pipe_entry *default_ingr_acl_entry{};
	struct doca_flow_pipe_entry *default_egr_sampling_entry{};
	struct doca_flow_pipe_entry *root_jump_to_ingress_ipv6_entry{};
	struct doca_flow_pipe_entry *root_jump_to_ingress_ipv4_entry{};
	struct doca_flow_pipe_entry *root_jump_to_egress_entry{};
	struct doca_flow_pipe_entry *vf_arp_to_rss{};
	struct doca_flow_pipe_entry *syndrome_stats_entries[NUM_OF_PSP_SYNDROMES]{};
	struct doca_flow_pipe_entry *empty_pipe_entry{};
	struct doca_flow_pipe_entry *root_default_drop{};

	struct doca_flow_monitor monitor_count{};

	// Shared resource IDs
	uint32_t mirror_res_id;
	uint32_t mirror_res_id_port;

	uint64_t prev_static_flow_count{UINT64_MAX};
};

#endif /* FLOWS_H_ */
