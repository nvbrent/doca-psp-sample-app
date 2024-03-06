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
 * @brief Maintains the state of the host PF
 */
struct psp_pf_dev {
	doca_dev *dev;
	uint16_t port_id;
	doca_flow_port *port_obj;

	rte_ether_addr src_mac;
	std::string src_mac_str;

	ipv6_addr_t src_pip; // Physical/Outer IP addr
	std::string src_pip_str;
};

/**
 * @brief describes a PSP tunnel connection to a single address
 *        on a remote host
 */
struct psp_session_t {
	rte_ether_addr dst_mac;

	ipv6_addr_t dst_pip; //!< Physical/Outer IP addr
	doca_be32_t dst_vip; //!< Virtual/Innter IP addr

	uint32_t spi;	    //!< Security Parameter Index on the wire
	uint32_t crypto_id; //!< Internal shared-resource index

	uint64_t vc; //!< Virtualization cookie, if enabled

	doca_flow_pipe_entry *encap_entry;
	doca_flow_pipe_entry *encrypt_entry;
	uint64_t pkt_count;
};

/**
 * @brief The entity which owns all the doca flow shared
 *        resources and flow pipes (but not sessions).
 */
class PSP_GatewayFlows {
public:
	/**
	 * @brief Constructs the object. This operation cannot fail.
	 * @param [in] pf The Host PF object, already opened and probed,
	 *        but not started, by DOCA, of the device which sends
	 *        and receives encrypted packets
	 * @param [in] vf_port_id The port_id of the device which sends
	 *        and received plaintext packets.
	 */
	PSP_GatewayFlows(psp_pf_dev *pf, uint16_t vf_port_id, psp_gw_app_config *app_config);

	/**
	 * Deallocates all associated DOCA objects.
	 * In case of failure, an error is logged and progress continues.
	 */
	virtual ~PSP_GatewayFlows(void);

	/**
	 * Exposes the host PF device. (Used by the benchmarking functions.)
	 */
	psp_pf_dev *pf()
	{
		return pf_dev;
	}

	/**
	 * @brief Initialized the DOCA resources.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t init(void);

	/**
	 * @brief Adds a flow pipe entry to perform encryption on a new flow
	 *        to the indicated remote host.
	 * The caller is responsible for negotiating the SPI and key, and
	 * assigning a unique crypto_id.
	 *
	 * @session [in]: the session for which an encryption flow should be created
	 * @encrypt_key [in]: the encryption key to use for the session
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t add_encrypt_entry(psp_session_t *session, const void *encrypt_key);

	/**
	 * @brief Removes the indicated flow entry.
	 *
	 * @session [in]: The session whose associated flows should be removed
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t remove_encrypt_entry(psp_session_t *session);

	/**
	 * @brief Shows flow counters for pipes which have a fixed number of entries,
	 *        if any counter values have changed since the last invocation.
	 */
	void show_static_flow_counts(void);

	/**
	 * @brief Shows flow counters for the given tunnel, if they have changed
	 *        since the last invocation.
	 *
	 * @dst_vip [in]: stringified dst IP, to avoid repeating the conversion
	 * @session [in/out]: the object which holds the flow entries
	 */
	void show_session_flow_count(const std::string &dst_vip, psp_session_t &session);

private:
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
	 * @brief handles the initialization of doca_flow
	 *
	 * @app_cfg [in]: the psp app configuration
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t init_doca_flow(const psp_gw_app_config *app_cfg);

	/**
	 * @brief handles the binding of the shared resources to ports
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t bind_shared_resources(void);

	/**
	 * @brief handles the setup of the packet mirroring shared resources
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t configure_mirrors(void);

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
	 * Generates the outer/encap header contents for a given session
	 *
	 * @session [in]: the remote host mac/ip/etc. to encap
	 * @encap_data [out]: the actions.crypto_encap.encap_data to populate
	 */
	void format_encap_data(const psp_session_t *session, uint8_t *encap_data);

	/**
	 * Top-level pipe creation method
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t create_pipes(void);

	/**
	 * Creates the PSP decryption pipe.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_decrypt_pipe_create(void);

	/**
	 * Creates the pipe to sample packets with the PSP.S bit set
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_sampling_pipe_create(void);

	/**
	 * Creates the pipe to only accept incoming packets from
	 * appropriate sources.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_acl_pipe_create(void);

	/**
	 * Creates the pipe which counts the various syndrome types
	 * and drops the packets
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t syndrome_stats_pipe_create(void);

	/**
	 * Creates the pipe to trap outgoing packets to unregistered destinations
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t egress_acl_pipe_create(void);

	/**
	 * Creates the pipe to mark and randomly sample outgoing packets
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t egress_sampling_pipe_create(void);

	/**
	 * Creates the encryption pipe
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t egress_encrypt_pipe_create(void);

	/**
	 * Creates the entry point to the CPU Rx queues
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t rss_pipe_create(void);

	/**
	 * @brief Creates the first pipe hit by packets arriving to
	 * the eswitch from either the uplink (wire) or the VF.
	 *
	 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
	 */
	doca_error_t ingress_root_pipe_create(void);

	// Application state data:

	psp_gw_app_config *app_config{};

	psp_pf_dev *pf_dev{};

	uint16_t vf_port_id{UINT16_MAX};

	doca_flow_port *vf_port{};

	// Pipe and pipe entry application state:

	// general pipes
	doca_flow_pipe *rss_pipe{};
	doca_flow_pipe *ingress_root_pipe{};

	// net-to-host pipes
	doca_flow_pipe *ingress_decrypt_pipe{};
	doca_flow_pipe *ingress_sampling_pipe{};
	doca_flow_pipe *ingress_acl_pipe{};

	// host-to-net pipes
	doca_flow_pipe *egress_acl_pipe{};
	doca_flow_pipe *egress_sampling_pipe{};
	doca_flow_pipe *egress_encrypt_pipe{};
	doca_flow_pipe *syndrome_stats_pipe{};

	// static pipe entries
	doca_flow_pipe_entry *default_rss_entry{};
	doca_flow_pipe_entry *default_decrypt_entry{};
	doca_flow_pipe_entry *default_ingr_sampling_entry{};
	doca_flow_pipe_entry *default_ingr_acl_entry{};
	doca_flow_pipe_entry *default_egr_sampling_entry{};
	doca_flow_pipe_entry *vf_arp_to_rss{};
	doca_flow_pipe_entry *syndrome_stats_entries[NUM_OF_PSP_SYNDROMES]{};

	// Shared resource IDs
	uint32_t ingress_mirror_id{};
	uint32_t egress_mirror_id{};

	// Sum of all static pipe entries the last time
	// show_static_flow_counts() was invoked.
	uint64_t prev_static_flow_count{UINT64_MAX};
};

#endif /* FLOWS_H_ */
