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

#include <string>
#include <vector>

#include <doca_flow.h>
#include <doca_flow_crypto.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <doca_dpdk.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <samples/common.h>
#include <rte_ip.h>

#include "psp_gw_config.h"
#include "psp_gw_flows.h"
#include "psp_gw_utils.h"

DOCA_LOG_REGISTER(PSP_GATEWAY);

static const uint32_t DEFAULT_TIMEOUT_US = 10000; /* default timeout for processing entries */
static const uint32_t PSP_ICV_SIZE = 16;
static const uint32_t MAX_ACTIONS_MEM_SIZE = 8388608 * 64;

/**
 * @brief packet header structure to simplify populating the encap_data array for encap ipv6 data
 */
struct eth_ipv6_psp_tunnel_hdr {
	// encapped Ethernet header contents.
	rte_ether_hdr eth;

	// encapped IP header contents (extension header not supported)
	rte_ipv6_hdr ip;

	rte_udp_hdr udp;

	// encapped PSP header contents.
	rte_psp_base_hdr psp;
	rte_be64_t psp_virt_cookie;

} __rte_packed __rte_aligned(2);

/**
 * @brief packet header structure to simplify populating the encap_data array for encap ipv4 data
 */
struct eth_ipv4_psp_tunnel_hdr {
	// encapped Ethernet header contents.
	rte_ether_hdr eth;

	// encapped IP header contents (extension header not supported)
	rte_ipv4_hdr ip;

	rte_udp_hdr udp;

	// encapped PSP header contents.
	rte_psp_base_hdr psp;
	rte_be64_t psp_virt_cookie;

} __rte_packed __rte_aligned(2);

const uint8_t PSP_SAMPLE_ENABLE = 1 << 7;

PSP_GatewayFlows::PSP_GatewayFlows(psp_gw_nic_desc_t &nic_info, psp_gw_app_config *app_config)
	: app_config(app_config),
	  nic_info(nic_info)
{
	monitor_count.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	for (uint32_t i = 0; i < app_config->crypto_ids_per_nic; i++) {
		available_crypto_ids.insert(app_config->next_crypto_id++);
	}
	mirror_res_id = app_config->next_mirror_id++;
	mirror_res_id_port = app_config->next_mirror_id++;
}

PSP_GatewayFlows::~PSP_GatewayFlows()
{
	DOCA_LOG_INFO("Destroying PSP Gateway Flows");
}

doca_error_t PSP_GatewayFlows::init_dev(void)
{
	doca_error_t result = DOCA_SUCCESS;

	std::string dev_probe_str = std::string("dv_flow_en=2,"	 // hardware steering
		"dv_xmeta_en=4,"	 // extended flow metadata support
		"fdb_def_rule_en=0," // disable default root flow table rule
		"vport_match=1,"
		"repr_matching_en=0,"
		"representor=") +
		nic_info.repr; // indicate which representors to probe

	IF_SUCCESS(result, open_doca_device_with_pci(nic_info.pci.c_str(), nullptr, &pf_dev.dev));
	IF_SUCCESS(result, doca_dpdk_port_probe(pf_dev.dev, dev_probe_str.c_str()));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to probe device %s: %s", nic_info.pci.c_str(), doca_error_get_descr(result));
		return result;
	}

	pf_dev.pf_port_id = app_config->next_port_id++;
	pf_dev.vf_port_id = app_config->next_port_id++;

	rte_eth_macaddr_get(pf_dev.pf_port_id, &pf_dev.pf_mac);
	pf_dev.pf_mac_str = mac_to_string(pf_dev.pf_mac);

	rte_eth_macaddr_get(pf_dev.vf_port_id, &pf_dev.vf_repr_mac);
	pf_dev.vf_repr_mac_str = mac_to_string(pf_dev.vf_repr_mac);

	if (app_config->outer == DOCA_FLOW_L3_TYPE_IP4) {
		pf_dev.local_pip.type = DOCA_FLOW_L3_TYPE_IP4;
		result = doca_devinfo_get_ipv4_addr(doca_dev_as_devinfo(pf_dev.dev),
						    (uint8_t *)&pf_dev.local_pip.ipv4_addr,
						    DOCA_DEVINFO_IPV4_ADDR_SIZE);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to find IPv4 addr for PF: %s", doca_error_get_descr(result));
			return result;
		}
		pf_dev.local_pip_str = ipv4_to_string(pf_dev.local_pip.ipv4_addr);
	} else {
		pf_dev.local_pip.type = DOCA_FLOW_L3_TYPE_IP6;
		result = doca_devinfo_get_ipv6_addr(doca_dev_as_devinfo(pf_dev.dev),
						    (uint8_t *)pf_dev.local_pip.ipv6_addr,
						    DOCA_DEVINFO_IPV6_ADDR_SIZE);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to find IPv6 addr for PF: %s", doca_error_get_descr(result));
			return result;
		}
		pf_dev.local_pip_str = ipv6_to_string(pf_dev.local_pip.ipv6_addr);
	}

	DOCA_LOG_INFO("Probed PF %s, VF %s on PCI %s", pf_dev.pf_mac_str.c_str(), pf_dev.vf_repr_mac_str.c_str(), nic_info.pci.c_str());
	return result;
}

doca_error_t PSP_GatewayFlows::init_flows(void)
{
	doca_error_t result = DOCA_SUCCESS;

	IF_SUCCESS(result, start_port(pf_dev.pf_port_id, pf_dev.dev, &pf_dev.pf_port));
	IF_SUCCESS(result, start_port(pf_dev.vf_port_id, nullptr, &pf_dev.vf_port));
	IF_SUCCESS(result, bind_shared_resources());
	IF_SUCCESS(result, create_pipes());

	set_pending_op_state(DOCA_FLOW_PORT_OPERATION_STATE_STANDBY);
	IF_SUCCESS(result, apply_pending_op_state());

	return result;
}

doca_error_t PSP_GatewayFlows::rotate_master_key(std::vector<psp_session_desc_t>& sessions_to_update) {
	doca_error_t result = doca_flow_crypto_psp_master_key_rotate(pf_dev.pf_port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to rotate master key: %s", doca_error_get_descr(result));
	}

	for (auto& session : ingress_sessions) {
		sessions_to_update.push_back(session.first);
	}
	return result;
}

std::vector<doca_error_t> PSP_GatewayFlows::create_ingress_paths(
	const std::vector<psp_session_desc_t> &sessions,
	std::vector<spi_key_t> &spi_keys)
{
	DOCA_LOG_INFO("Creating ingress paths");

	// Bulk generate SPIs and keys
	doca_error_t result = DOCA_SUCCESS;

	std::vector<uint32_t> spis(sessions.size());
	std::vector<uint32_t[8]> keys(sessions.size());
	result = generate_keys_spis(
		psp_version_to_key_length_bits(app_config->net_config.default_psp_proto_ver),
		sessions.size(),
		(uint32_t *)keys.data(),
		spis.data()
	);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to generate keys and spis: %s", doca_error_get_descr(result));
		return std::vector<doca_error_t>(sessions.size(), result);
	}

	for (size_t i = 0; i < sessions.size(); ++i) {
		spi_key_t spi_key = {};
		spi_key.spi = spis[i];
		memcpy(spi_key.key, keys[i], sizeof(spi_key.key));
		spi_keys.push_back(spi_key);
	}

	std::vector<doca_error_t> results(sessions.size());
	for(size_t i = 0; i < sessions.size(); ++i) {
		auto &session = sessions[i];
		auto &spi_key = spi_keys[i];

		bool update_existing_session = ingress_sessions.find(session) != ingress_sessions.end();
		assert(!(session.local_vip.empty() || session.remote_vip.empty() || session.remote_pip.empty()));

		psp_session_ingress_t new_session = {};
		new_session.ingress_acl_entry = nullptr;
		new_session.pkt_count_ingress = UINT64_MAX;
		if (update_existing_session) {
			new_session.expiring_ingress_acl_entry = ingress_sessions[session].ingress_acl_entry;
		}

		result = add_ingress_acl_entry(session, spi_key.spi, &new_session.ingress_acl_entry);
		if (result == DOCA_SUCCESS) {
			ingress_sessions[session] = new_session;
		}
		results[i] = result;
	}

	assert(results.size() == sessions.size());
	return results;
}

std::vector<doca_error_t> PSP_GatewayFlows::expire_ingress_paths(
	const std::vector<psp_session_desc_t> &sessions,
	const std::vector<bool> expire_old)
{
	std::vector<doca_error_t> results(sessions.size(), DOCA_SUCCESS);
	if (app_config->disable_ingress_acl) {
		return results;
	}

	for (size_t i = 0; i < sessions.size(); ++i) {
		const psp_session_desc_t &session = sessions[i];
		bool exp_old = expire_old[i];

		assert(!(session.local_vip.empty() || session.remote_vip.empty() || session.remote_pip.empty()));

		doca_flow_pipe_entry *expiring_entry = nullptr;
		if (exp_old) {
			expiring_entry = ingress_sessions[session].expiring_ingress_acl_entry;
		} else {
			expiring_entry = ingress_sessions[session].ingress_acl_entry;
			ingress_sessions[session].ingress_acl_entry = ingress_sessions[session].expiring_ingress_acl_entry;
		}
		ingress_sessions[session].expiring_ingress_acl_entry = nullptr;

		// At this point:
		// - expiring_entry points to the entry that should be removed
		// - ingress_sessions[session].ingress_acl_entry points to the entry that should be kept
		// - ingress_sessions[session].expiring_ingress_acl_entry is nullptr

		if (expiring_entry) {
			DOCA_LOG_INFO("Removing expired ingress path %s<-%s", session.local_vip.c_str(), session.remote_vip.c_str());
			results[i] = remove_single_entry(expiring_entry);
		}

		// In case we added an ingress ACL entry, then the remote side did not succeed,
		// we have no ingress entries and we need to remove the ingress session altogether
		if (!ingress_sessions[session].ingress_acl_entry) {
			ingress_sessions.erase(session);
		}
	}

	assert(results.size() == sessions.size());
	return results;
}

doca_error_t PSP_GatewayFlows::set_egress_path(const psp_session_desc_t &session, const spi_keyptr_t &spi_key) {
	assert(!(session.local_vip.empty() || session.remote_vip.empty() || session.remote_pip.empty()));

	doca_error_t result = DOCA_SUCCESS;
	bool update_existing_session = egress_sessions.find(session) != egress_sessions.end();
	struct doca_flow_shared_resource_cfg res_cfg = {};
	uint32_t old_crypto_id = UINT32_MAX;
	psp_session_egress_t new_session = {};

	new_session.pkt_count_egress = UINT64_MAX;

	if (update_existing_session) {
		old_crypto_id = egress_sessions[session].crypto_id;
		new_session.encap_encrypt_entry = egress_sessions[session].encap_encrypt_entry;
	}

	new_session.crypto_id = allocate_crypto_id();
	if (new_session.crypto_id == UINT32_MAX) {
		DOCA_LOG_ERR("Failed to allocate crypto id");
		result = DOCA_ERROR_NO_MEMORY;
		goto cleanup;
	}

	// Bind key to the crypto id
	res_cfg.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS;
	res_cfg.psp_cfg.key_cfg.key_type = app_config->net_config.default_psp_proto_ver == 0 ? DOCA_FLOW_CRYPTO_KEY_128 : DOCA_FLOW_CRYPTO_KEY_256;
	res_cfg.psp_cfg.key_cfg.key = (uint32_t *)spi_key.key;

	result = doca_flow_shared_resource_set_cfg(DOCA_FLOW_SHARED_RESOURCE_PSP, new_session.crypto_id, &res_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to configure crypto_id %d: %s", new_session.crypto_id, doca_error_get_descr(result));
		goto cleanup;
	}

	// Note: If there is no current entry, we will create a new one. If there is an
	//       existing entry, we will update it with the new SPI and crypto id
	result = config_encrypt_entry(session, spi_key.spi, new_session.crypto_id, &new_session.encap_encrypt_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to %s encrypt entry: %s", update_existing_session ? "update" : "add", doca_error_get_descr(result));
		goto cleanup;
	}

	// Update the session to reflect the new state
	egress_sessions[session] = new_session;

cleanup:
	if (update_existing_session) {
		release_crypto_id(result == DOCA_SUCCESS ? old_crypto_id : new_session.crypto_id);
	}

	return result;
}

std::vector<doca_error_t> PSP_GatewayFlows::set_egress_paths(
	const std::vector<psp_session_desc_t> &sessions,
	const std::vector<spi_keyptr_t> &spi_keys)
{
	assert(sessions.size() == spi_keys.size());

	std::vector<doca_error_t> results(sessions.size());
	for(size_t i = 0; i < sessions.size(); ++i) {

		results[i] = set_egress_path(sessions[i], spi_keys[i]);
	}
	return results;
}

doca_error_t PSP_GatewayFlows::configure_mirrors(void)
{
	assert(rss_pipe_ingress);
	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_mirror_target mirr_tgt = {};
	mirr_tgt.fwd.type = DOCA_FLOW_FWD_PIPE;
	mirr_tgt.fwd.next_pipe = rss_pipe_ingress;

	struct doca_flow_shared_resource_cfg res_cfg = {};
	res_cfg.domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS;
	res_cfg.mirror_cfg.nr_targets = 1;
	res_cfg.mirror_cfg.target = &mirr_tgt;

	IF_SUCCESS(result,
		   doca_flow_shared_resource_set_cfg(DOCA_FLOW_SHARED_RESOURCE_MIRROR, mirror_res_id, &res_cfg));

	IF_SUCCESS(
		result,
		doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_MIRROR, &mirror_res_id, 1, pf_dev.pf_port));

	doca_flow_mirror_target mirr_tgt_port = {};
	mirr_tgt_port.fwd.type = DOCA_FLOW_FWD_PORT;
	mirr_tgt_port.fwd.port_id = pf_dev.pf_port_id;

	res_cfg.mirror_cfg.target = &mirr_tgt_port;

	IF_SUCCESS(result,
		   doca_flow_shared_resource_set_cfg(DOCA_FLOW_SHARED_RESOURCE_MIRROR, mirror_res_id_port, &res_cfg));
	IF_SUCCESS(result,
		   doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_MIRROR,
						   &mirror_res_id_port,
						   1,
						   pf_dev.pf_port));

	return result;
}

doca_error_t PSP_GatewayFlows::create_pipes(void)
{
	doca_error_t result = DOCA_SUCCESS;

	IF_SUCCESS(result, rss_pipe_create(true));
	IF_SUCCESS(result, rss_pipe_create(false));
	IF_SUCCESS(result, configure_mirrors());
	IF_SUCCESS(result, syndrome_stats_pipe_create());
	IF_SUCCESS(result, ingress_acl_pipe_create());
	if (sampling_enabled()) {
		IF_SUCCESS(result, ingress_sampling_pipe_create());
	}
	IF_SUCCESS(result, ingress_decrypt_pipe_create());
	if (sampling_enabled()) {
		IF_SUCCESS(result, empty_pipe_create_not_sampled());
		IF_SUCCESS(result, egress_sampling_pipe_create());
	}
	IF_SUCCESS(result, egress_acl_pipe_create());
	IF_SUCCESS(result, empty_pipe_create(egress_acl_pipe));
	IF_SUCCESS(result, ingress_root_pipe_create());

	if (result == DOCA_SUCCESS)
		DOCA_LOG_INFO("Created all static pipes on port %d", pf_dev.pf_port_id);
	else
		DOCA_LOG_ERR("Failed to create all static pipes on port %d, err: %s", pf_dev.pf_port_id, doca_error_get_descr(result));

	return result;
}

doca_error_t PSP_GatewayFlows::start_port(uint16_t port_id, doca_dev *port_dev, doca_flow_port **port)
{
	doca_flow_port_cfg *port_cfg;
	doca_error_t result = DOCA_SUCCESS;

	IF_SUCCESS(result, doca_flow_port_cfg_create(&port_cfg));

	std::string port_id_str = std::to_string(port_id); // note that set_devargs() clones the string contents
	IF_SUCCESS(result, doca_flow_port_cfg_set_devargs(port_cfg, port_id_str.c_str()));
	IF_SUCCESS(result, doca_flow_port_cfg_set_dev(port_cfg, port_dev));
    IF_SUCCESS(result, doca_flow_port_cfg_set_actions_mem_size(port_cfg, rte_align32pow2(MAX_ACTIONS_MEM_SIZE)));
	if (port_dev) {
		IF_SUCCESS(result, doca_flow_port_cfg_set_operation_state(port_cfg, op_state));
	}
	IF_SUCCESS(result, doca_flow_port_start(port_cfg, port));
	if (result == DOCA_SUCCESS) {
		rte_ether_addr port_mac_addr;
		rte_eth_macaddr_get(port_id, &port_mac_addr);
		DOCA_LOG_INFO("Started port_id %d, mac-addr: %s", port_id, mac_to_string(port_mac_addr).c_str());
	}

	if (port_cfg) {
		doca_flow_port_cfg_destroy(port_cfg);
	}
	return result;
}

void PSP_GatewayFlows::set_pending_op_state(doca_flow_port_operation_state new_op_state)
{
	this->pending_op_state = new_op_state;
}

doca_error_t PSP_GatewayFlows::apply_pending_op_state()
{
	if (this->op_state == this->pending_op_state) {
		return DOCA_ERROR_SKIPPED;
	}

	doca_error_t result = doca_flow_port_operation_state_modify(pf_dev.pf_port, this->pending_op_state);
	if (result != DOCA_SUCCESS) {
		std::string failure = "Failed to set operational state: " + std::to_string(result) + " (" +
				      doca_error_get_descr(result) + ")";
		DOCA_LOG_ERR("%s", failure.c_str());
		return DOCA_ERROR_DRIVER;
	}

	this->op_state = this->pending_op_state;
	return result;
}

doca_error_t PSP_GatewayFlows::bind_shared_resources(void)
{
	doca_error_t result = DOCA_SUCCESS;

	std::vector<uint32_t> psp_ids(available_crypto_ids.begin(), available_crypto_ids.end());

	IF_SUCCESS(result,
		   doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_PSP,
						   psp_ids.data(),
						   psp_ids.size(),
						   pf_dev.pf_port));

	return result;
}

doca_error_t PSP_GatewayFlows::update_single_entry(uint16_t pipe_queue,
						doca_flow_pipe *pipe,
						const doca_flow_match *match,
						const doca_flow_actions *actions,
						const doca_flow_monitor *mon,
						const doca_flow_fwd *fwd,
						doca_flow_pipe_entry *entry)
{
	doca_error_t result = doca_flow_pipe_update_entry(0, pipe, actions, mon, fwd, DOCA_FLOW_NO_WAIT, entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to update encrypt_encap pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(pf_dev.pf_port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entry: %s", doca_error_get_descr(result));
		return result;
	}

	return result;
}

doca_error_t PSP_GatewayFlows::add_single_entry(uint16_t pipe_queue,
						doca_flow_pipe *pipe,
						doca_flow_port *port,
						const doca_flow_match *match,
						const doca_flow_actions *actions,
						const doca_flow_monitor *mon,
						const doca_flow_fwd *fwd,
						doca_flow_pipe_entry **entry)
{
	int num_of_entries = 1;
	uint32_t flags = DOCA_FLOW_NO_WAIT;

	struct entries_status status = {};
	status.entries_in_queue = num_of_entries;

	doca_error_t result =
		doca_flow_pipe_add_entry(pipe_queue, pipe, match, actions, mon, fwd, flags, &status, entry);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(port, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entry: %s", doca_error_get_descr(result));
		return result;
	}

	if (status.nb_processed != num_of_entries || status.failure) {
		DOCA_LOG_ERR("Failed to process entry; nb_processed = %d, failure = %d",
			     status.nb_processed,
			     status.failure);
		return DOCA_ERROR_BAD_STATE;
	}

	return result;
}

doca_error_t PSP_GatewayFlows::rss_pipe_create(bool ingress)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match empty_match = {};

	// Note packets sent to RSS will be processed by lcore_pkt_proc_func().
	uint16_t rss_queues[1] = {0};
	struct doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	fwd.rss.outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6;
	fwd.rss.nr_queues = 1;
	fwd.rss.queues_array = rss_queues;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, ingress ? "RSS_PIPE_INGRESS" : "RSS_PIPE_EGRESS"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, ingress ? DOCA_FLOW_PIPE_DOMAIN_DEFAULT : DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &empty_match, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, nullptr, ingress ? &rss_pipe_ingress : &rss_pipe_egress));
	IF_SUCCESS(
		result,
		add_single_entry(0, ingress ? rss_pipe_ingress : rss_pipe_egress, pf_dev.pf_port, nullptr, nullptr, nullptr, nullptr, ingress ? &default_rss_entry_ingress : &default_rss_entry_egress));

	if (pipe_cfg)
		doca_flow_pipe_cfg_destroy(pipe_cfg);

	return result;
}

doca_error_t PSP_GatewayFlows::syndrome_stats_pipe_create(void)
{
	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match syndrome_match = {};
	syndrome_match.parser_meta.psp_syndrome = 0xff;

	// If we got here, the packet failed either the PSP decryption syndrome check
	// or the ACL check. Whether the syndrome bits match here or not, the
	// fate of the packet is to drop.
	struct doca_flow_fwd fwd_drop = {};
	fwd_drop.type = DOCA_FLOW_FWD_DROP;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "SYNDROME_STATS"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NUM_OF_PSP_SYNDROMES));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_NETWORK_TO_HOST));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &syndrome_match, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_drop, &fwd_drop, &syndrome_stats_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	for (int i = 0; i < NUM_OF_PSP_SYNDROMES; i++) {
		syndrome_match.parser_meta.psp_syndrome = 1 << i;
		IF_SUCCESS(result,
			   add_single_entry(0,
					    syndrome_stats_pipe,
					    pf_dev.pf_port,
					    &syndrome_match,
					    nullptr,
					    &monitor_count,
					    nullptr,
					    &syndrome_stats_entries[i]));
	}

	return result;
}

doca_error_t PSP_GatewayFlows::ingress_acl_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	doca_error_t result = DOCA_SUCCESS;
	struct doca_flow_match match = {};
	match.parser_meta.psp_syndrome = UINT8_MAX;
	if (!app_config->disable_ingress_acl) {
		match.tun.type = DOCA_FLOW_TUN_PSP;
		match.tun.psp.spi = UINT32_MAX;
		match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
		match.inner.ip4.src_ip = UINT32_MAX;
	}

	struct doca_flow_actions actions = {};
	actions.has_crypto_encap = true;
	actions.crypto_encap.action_type = DOCA_FLOW_CRYPTO_REFORMAT_DECAP;
	actions.crypto_encap.net_type = DOCA_FLOW_CRYPTO_HEADER_PSP_TUNNEL;
	actions.crypto_encap.icv_size = PSP_ICV_SIZE;
	actions.crypto_encap.data_size = sizeof(rte_ether_hdr);

	struct rte_ether_hdr *eth_hdr = (rte_ether_hdr *)actions.crypto_encap.encap_data;
	eth_hdr->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	eth_hdr->src_addr = pf_dev.pf_mac;
	eth_hdr->dst_addr = nic_info.vfmac;

	doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = pf_dev.vf_port_id;

	struct doca_flow_fwd fwd_miss = {};
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = syndrome_stats_pipe;

	// During key rotation, we temporarily keep ingress sessions open for both the old and new keys,
	// so we can have number of entries == number of sessions * 2
	int nr_entries = app_config->disable_ingress_acl ? 1 : app_config->max_tunnels * 2;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "INGR_ACL"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, nr_entries));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_NETWORK_TO_HOST));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &ingress_acl_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	if (app_config->disable_ingress_acl) {
		doca_flow_match match_no_syndrome = {};
		IF_SUCCESS(result,
			   add_single_entry(0,
					    ingress_acl_pipe,
					    pf_dev.pf_port,
					    &match_no_syndrome,
					    &actions,
					    nullptr,
					    nullptr,
					    &default_ingr_acl_entry));
	}

	return result;
}

doca_error_t PSP_GatewayFlows::ingress_sampling_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(mirror_res_id);
	assert(rss_pipe_ingress);
	assert(sampling_enabled());
	doca_error_t result = DOCA_SUCCESS;

	struct doca_flow_match match_psp_sampling_bit = {};
	match_psp_sampling_bit.tun.type = DOCA_FLOW_TUN_PSP;
	match_psp_sampling_bit.tun.psp.s_d_ver_v = PSP_SAMPLE_ENABLE;

	struct doca_flow_monitor mirror_action = {};
	mirror_action.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	mirror_action.shared_mirror_id = mirror_res_id;

	struct doca_flow_actions set_meta = {};
	set_meta.meta.pkt_meta = rte_cpu_to_be_32(app_config->ingress_sample_meta_indicator);

	struct doca_flow_actions *actions_arr[] = {&set_meta};

	struct doca_flow_actions set_meta_mask = {};
	set_meta_mask.meta.pkt_meta = UINT32_MAX;

	struct doca_flow_actions *actions_masks_arr[] = {&set_meta_mask};

	struct doca_flow_fwd fwd_and_miss = {};
	fwd_and_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_and_miss.next_pipe = ingress_acl_pipe;

	struct doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "INGR_SAMPL"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, actions_masks_arr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_psp_sampling_bit, &match_psp_sampling_bit));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, actions_masks_arr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mirror_action));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_and_miss, &fwd_and_miss, &ingress_sampling_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	IF_SUCCESS(result,
		   add_single_entry(0,
				    ingress_sampling_pipe,
				    pf_dev.pf_port,
				    nullptr,
				    nullptr,
				    nullptr,
				    nullptr,
				    &default_ingr_sampling_entry));

	return result;
}

doca_error_t PSP_GatewayFlows::ingress_decrypt_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(sampling_enabled() ? ingress_sampling_pipe : ingress_acl_pipe);
	assert(rss_pipe_ingress);
	doca_error_t result = DOCA_SUCCESS;

	doca_flow_match match = {};
	match.parser_meta.port_meta = UINT32_MAX;
	match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
	match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP;
	match.outer.udp.l4_port.dst_port = RTE_BE16(DOCA_FLOW_PSP_DEFAULT_PORT);

	doca_flow_actions actions = {};
	actions.crypto.action_type = DOCA_FLOW_CRYPTO_ACTION_DECRYPT;
	actions.crypto.resource_type = DOCA_FLOW_CRYPTO_RESOURCE_PSP;
	actions.crypto.crypto_id = DOCA_FLOW_PSP_DECRYPTION_ID;

	doca_flow_actions *actions_arr[] = {&actions};

	doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_PIPE;
	fwd.next_pipe = sampling_enabled() ? ingress_sampling_pipe : ingress_acl_pipe;

	doca_flow_fwd fwd_miss = {};
	fwd_miss.type = DOCA_FLOW_FWD_DROP;

	doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "PSP_DECRYPT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_NETWORK_TO_HOST));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &ingress_decrypt_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	doca_flow_match match_uplink = {};
	match_uplink.parser_meta.port_meta = 0;

	IF_SUCCESS(result,
		   add_single_entry(0,
				    ingress_decrypt_pipe,
				    pf_dev.pf_port,
				    &match_uplink,
				    &actions,
				    nullptr,
				    nullptr,
				    &default_decrypt_entry));

	return result;
}

doca_error_t PSP_GatewayFlows::empty_pipe_create_not_sampled(void)
{
	doca_error_t result = DOCA_SUCCESS;
	doca_flow_match match = {};

	doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = pf_dev.pf_port_id;

	doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "EMPTY_NOT_SAMPLED"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, false));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, nullptr, &empty_pipe_not_sampled));
	IF_SUCCESS(result,
		   add_single_entry(0,
				    empty_pipe_not_sampled,
				    pf_dev.pf_port,
				    nullptr,
				    nullptr,
				    nullptr,
				    nullptr,
				    &empty_pipe_entry));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	return result;
}

doca_error_t PSP_GatewayFlows::egress_sampling_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(sampling_enabled());

	doca_error_t result = DOCA_SUCCESS;

	uint16_t mask = (uint16_t)((1 << app_config->log2_sample_rate) - 1);
	DOCA_LOG_DBG("Sampling: matching (rand & 0x%x) == 1", mask);

	doca_flow_match match_sampling_match_mask = {};
	match_sampling_match_mask.parser_meta.random = mask;

	doca_flow_match match_sampling_match = {};
	match_sampling_match.parser_meta.random = 0x1;

	doca_flow_actions set_sample_bit = {};
	set_sample_bit.meta.pkt_meta = rte_cpu_to_be_32(app_config->egress_sample_meta_indicator);
	set_sample_bit.tun.type = DOCA_FLOW_TUN_PSP;
	set_sample_bit.tun.psp.s_d_ver_v = PSP_SAMPLE_ENABLE;
	doca_flow_actions *actions_arr[] = {&set_sample_bit};

	doca_flow_actions actions_mask = {};
	actions_mask.meta.pkt_meta = UINT32_MAX;
	actions_mask.tun.type = DOCA_FLOW_TUN_PSP;
	actions_mask.tun.psp.s_d_ver_v = PSP_SAMPLE_ENABLE;
	doca_flow_actions *actions_masks_arr[] = {&actions_mask};

	doca_flow_monitor mirror_action = {};
	mirror_action.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	mirror_action.shared_mirror_id = mirror_res_id_port;

	doca_flow_fwd fwd_miss = {}; /* going through an empty pipe that will forward to port */
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = empty_pipe_not_sampled;

	doca_flow_fwd fwd_rss = {};
	fwd_rss.type = DOCA_FLOW_FWD_PIPE;
	fwd_rss.next_pipe = rss_pipe_egress;

	doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "EGR_SAMPL"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_sampling_match, &match_sampling_match_mask));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, actions_masks_arr, nullptr, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &mirror_action));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd_rss, &fwd_miss, &egress_sampling_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	IF_SUCCESS(result,
		   add_single_entry(0,
				    egress_sampling_pipe,
				    pf_dev.pf_port,
				    nullptr,
				    nullptr,
				    nullptr,
				    nullptr,
				    &default_egr_sampling_entry));

	return result;
}

doca_error_t PSP_GatewayFlows::egress_acl_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(rss_pipe_egress);
	assert(!sampling_enabled() || egress_sampling_pipe);
	doca_error_t result = DOCA_SUCCESS;

	doca_flow_match match = {};
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.dst_ip = UINT32_MAX;
	match.outer.ip4.src_ip = UINT32_MAX;

	doca_flow_actions actions = {};
	doca_flow_actions encap_ipv4 = {};
	doca_flow_actions encap_ipv6 = {};

	actions.has_crypto_encap = true;
	actions.crypto_encap.action_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP;
	actions.crypto_encap.net_type = DOCA_FLOW_CRYPTO_HEADER_PSP_TUNNEL;
	actions.crypto_encap.icv_size = PSP_ICV_SIZE;
	actions.crypto.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT;
	actions.crypto.resource_type = DOCA_FLOW_CRYPTO_RESOURCE_PSP;
	actions.crypto.crypto_id = UINT32_MAX; // per entry

	encap_ipv6 = actions;
	encap_ipv4 = actions;

	encap_ipv6.crypto_encap.data_size = sizeof(eth_ipv6_psp_tunnel_hdr);
	encap_ipv4.crypto_encap.data_size = sizeof(eth_ipv4_psp_tunnel_hdr);

	if (!app_config->net_config.vc_enabled) {
		encap_ipv6.crypto_encap.data_size -= sizeof(uint64_t);
		encap_ipv4.crypto_encap.data_size -= sizeof(uint64_t);
	}
	memset(encap_ipv6.crypto_encap.encap_data, 0xff, encap_ipv6.crypto_encap.data_size);
	memset(encap_ipv4.crypto_encap.encap_data, 0xff, encap_ipv4.crypto_encap.data_size);

	doca_flow_actions *actions_arr[] = {&encap_ipv6, &encap_ipv4};

	doca_flow_fwd fwd_to_sampling = {};
	fwd_to_sampling.type = DOCA_FLOW_FWD_PIPE;
	fwd_to_sampling.next_pipe = egress_sampling_pipe;

	doca_flow_fwd fwd_to_wire = {};
	fwd_to_wire.type = DOCA_FLOW_FWD_PORT;
	fwd_to_wire.port_id = pf_dev.pf_port_id;

	auto p_fwd = sampling_enabled() ? &fwd_to_sampling : &fwd_to_wire;

	doca_flow_fwd fwd_miss = {};
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = rss_pipe_egress;

	doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "EGR_ACL"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, app_config->max_tunnels));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_dir_info(pipe_cfg, DOCA_FLOW_DIRECTION_HOST_TO_NETWORK));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, nullptr, nullptr, 2));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, p_fwd, &fwd_miss, &egress_acl_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	return result;
}

doca_error_t PSP_GatewayFlows::empty_pipe_create(doca_flow_pipe *next_pipe)
{
	doca_error_t result = DOCA_SUCCESS;

	doca_flow_match match_arp = {};
	match_arp.outer.eth.type = RTE_BE16(DOCA_FLOW_ETHER_TYPE_ARP);

	doca_flow_fwd fwd = {};
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = pf_dev.vf_port_id;

	doca_flow_fwd fwd_miss = {};
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = next_pipe;

	doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "EMPTY"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_domain(pipe_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 1));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_match(pipe_cfg, &match_arp, nullptr));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_count));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_miss_counter(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, &empty_pipe));

	IF_SUCCESS(
		result,
		add_single_entry(0, empty_pipe, pf_dev.pf_port, nullptr, nullptr, nullptr, nullptr, &empty_pipe_entry));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	return result;
}

doca_error_t PSP_GatewayFlows::ingress_root_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(ingress_decrypt_pipe);
	assert(egress_acl_pipe);
	doca_error_t result = DOCA_SUCCESS;

	doca_flow_pipe_cfg *pipe_cfg;
	IF_SUCCESS(result, doca_flow_pipe_cfg_create(&pipe_cfg, pf_dev.pf_port));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_name(pipe_cfg, "ROOT"));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_type(pipe_cfg, DOCA_FLOW_PIPE_CONTROL));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_is_root(pipe_cfg, true));
	IF_SUCCESS(result, doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 5));
	IF_SUCCESS(result, doca_flow_pipe_create(pipe_cfg, nullptr, nullptr, &ingress_root_pipe));

	if (pipe_cfg) {
		doca_flow_pipe_cfg_destroy(pipe_cfg);
	}

	// Note outer_l4_ok can be matched with spec=true, mask=UINT8_MAX to
	// restrict traffic to TCP/UDP (ICMP would miss to RSS).
	doca_flow_match mask = {};
	mask.parser_meta.port_meta = UINT32_MAX;
	mask.parser_meta.outer_l3_ok = UINT8_MAX;
	mask.parser_meta.outer_ip4_checksum_ok = UINT8_MAX;
	mask.outer.eth.type = UINT16_MAX;

	doca_flow_match ipv6_from_uplink = {};
	ipv6_from_uplink.parser_meta.port_meta = pf_dev.pf_port_id;
	ipv6_from_uplink.parser_meta.outer_l3_ok = true;
	ipv6_from_uplink.parser_meta.outer_ip4_checksum_ok = false;
	ipv6_from_uplink.outer.eth.type = RTE_BE16(RTE_ETHER_TYPE_IPV6);

	doca_flow_match ipv4_from_uplink = {};
	ipv4_from_uplink.parser_meta.port_meta = pf_dev.pf_port_id;
	ipv4_from_uplink.parser_meta.outer_l3_ok = true;
	ipv4_from_uplink.parser_meta.outer_ip4_checksum_ok = true;
	ipv4_from_uplink.outer.eth.type = RTE_BE16(RTE_ETHER_TYPE_IPV4);

	doca_flow_match ipv4_from_vf = {};
	ipv4_from_vf.parser_meta.port_meta = pf_dev.vf_port_id;
	ipv4_from_vf.parser_meta.outer_l3_ok = true;
	ipv4_from_vf.parser_meta.outer_ip4_checksum_ok = true;
	ipv4_from_vf.outer.eth.type = RTE_BE16(RTE_ETHER_TYPE_IPV4);

	doca_flow_match arp_mask = {};
	arp_mask.parser_meta.port_meta = UINT32_MAX;
	arp_mask.outer.eth.type = UINT16_MAX;

	doca_flow_match arp_from_vf = {};
	arp_from_vf.parser_meta.port_meta = pf_dev.vf_port_id;
	arp_from_vf.outer.eth.type = RTE_BE16(DOCA_FLOW_ETHER_TYPE_ARP);

	doca_flow_match empty_match = {};

	doca_flow_fwd fwd_ingress = {};
	fwd_ingress.type = DOCA_FLOW_FWD_PIPE;
	fwd_ingress.next_pipe = ingress_decrypt_pipe;

	doca_flow_fwd fwd_egress = {};
	fwd_egress.type = DOCA_FLOW_FWD_PIPE;
	fwd_egress.next_pipe = empty_pipe; // and then to egress_acl_pipe

	doca_flow_fwd fwd_rss = {};
	fwd_rss.type = DOCA_FLOW_FWD_PIPE;
	fwd_rss.next_pipe = rss_pipe_ingress;

	doca_flow_fwd fwd_miss = {};
	fwd_miss.type = DOCA_FLOW_FWD_DROP;

	uint16_t pipe_queue = 0;

	IF_SUCCESS(result,
		   doca_flow_pipe_control_add_entry(pipe_queue,
						    1,
						    ingress_root_pipe,
						    &ipv6_from_uplink,
						    &mask,
						    nullptr,
						    nullptr,
						    nullptr,
						    nullptr,
						    &monitor_count,
						    &fwd_ingress,
						    nullptr,
						    &root_jump_to_ingress_ipv6_entry));

	IF_SUCCESS(result,
		   doca_flow_pipe_control_add_entry(pipe_queue,
						    1,
						    ingress_root_pipe,
						    &ipv4_from_uplink,
						    &mask,
						    nullptr,
						    nullptr,
						    nullptr,
						    nullptr,
						    &monitor_count,
						    &fwd_ingress,
						    nullptr,
						    &root_jump_to_ingress_ipv4_entry));

	IF_SUCCESS(result,
		   doca_flow_pipe_control_add_entry(pipe_queue,
						    2,
						    ingress_root_pipe,
						    &ipv4_from_vf,
						    &mask,
						    nullptr,
						    nullptr,
						    nullptr,
						    nullptr,
						    &monitor_count,
						    &fwd_egress,
						    nullptr,
						    &root_jump_to_egress_entry));

	IF_SUCCESS(result,
		   doca_flow_pipe_control_add_entry(pipe_queue,
						    3,
						    ingress_root_pipe,
						    &arp_from_vf,
						    &arp_mask,
						    nullptr,
						    nullptr,
						    nullptr,
						    nullptr,
						    &monitor_count,
						    &fwd_rss,
						    nullptr,
						    &vf_arp_to_rss));
	/* default miss in switch mode goes to NIC domain. this entry ensures to drop a non-matched packet */
	IF_SUCCESS(result,
		   doca_flow_pipe_control_add_entry(pipe_queue,
						    4,
						    ingress_root_pipe,
						    &empty_match,
						    &empty_match,
						    nullptr,
						    nullptr,
						    nullptr,
						    nullptr,
						    &monitor_count,
						    &fwd_miss,
						    nullptr,
						    &root_default_drop));

	return result;
}

uint32_t PSP_GatewayFlows::allocate_crypto_id(void)
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

void PSP_GatewayFlows::release_crypto_id(uint32_t crypto_id)
{
	if (available_crypto_ids.find(crypto_id) != available_crypto_ids.end()) {
		DOCA_LOG_WARN("Crypto ID %d already released", crypto_id);
	}
	DOCA_LOG_DBG("Released crypto_id %d", crypto_id);
	available_crypto_ids.insert(crypto_id);
}


doca_error_t PSP_GatewayFlows::generate_keys_spis(uint32_t key_len_bits,
						 uint32_t nr_keys_spis,
						 uint32_t *keys,
						 uint32_t *spis)
{
	doca_error_t result;
	struct doca_flow_crypto_psp_spi_key_bulk *bulk_key_gen = nullptr;

	auto key_type = key_len_bits == 128 ? DOCA_FLOW_CRYPTO_KEY_128 : DOCA_FLOW_CRYPTO_KEY_256;
	auto key_array_size = key_len_bits / 32; // 32-bit words

	DOCA_LOG_DBG("Generating %d SPI/Key pairs", nr_keys_spis);

	result = doca_flow_crypto_psp_spi_key_bulk_alloc(pf_dev.pf_port, key_type, nr_keys_spis, &bulk_key_gen);
	if (result != DOCA_SUCCESS || !bulk_key_gen) {
		DOCA_LOG_ERR("Failed to allocate bulk-key-gen object: %s", doca_error_get_descr(result));
		return DOCA_ERROR_NO_MEMORY;
	}

	uint64_t start_time = rte_get_tsc_cycles();
	result = doca_flow_crypto_psp_spi_key_bulk_generate(bulk_key_gen);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to generate keys and SPIs: %s", doca_error_get_descr(result));
		doca_flow_crypto_psp_spi_key_bulk_free(bulk_key_gen);
		return DOCA_ERROR_IO_FAILED;
	}

	for (uint32_t i = 0; i < nr_keys_spis; i++) {
		uint32_t *cur_key = keys + (i * key_array_size);
		result = doca_flow_crypto_psp_spi_key_bulk_get(bulk_key_gen, i, &spis[i], cur_key);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to retrieve SPI/Key: %s", doca_error_get_descr(result));
			doca_flow_crypto_psp_spi_key_bulk_free(bulk_key_gen);
			return DOCA_ERROR_IO_FAILED;
		}
	}

	uint64_t end_time = rte_get_tsc_cycles();
	double total_time = (end_time - start_time) / (double)rte_get_tsc_hz();
	double kilo_kps = 1e-3 * nr_keys_spis / total_time;
	if (app_config->print_perf_flags & PSP_PERF_KEY_GEN_PRINT) {
		DOCA_LOG_INFO("Generated %d SPI/Key pairs in %f seconds, %f KILO-KPS",
			      nr_keys_spis,
			      total_time,
			      kilo_kps);
	}

	doca_flow_crypto_psp_spi_key_bulk_free(bulk_key_gen);

	return DOCA_SUCCESS;
}

void PSP_GatewayFlows::format_encap_data_ipv6(const psp_session_desc_t &session, uint32_t spi, uint8_t *encap_data)
{
	static const doca_be32_t DEFAULT_VTC_FLOW = 0x6 << 28;

	auto *encap_hdr = (eth_ipv6_psp_tunnel_hdr *)encap_data;

	encap_hdr->eth.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
	encap_hdr->ip.vtc_flow = RTE_BE32(DEFAULT_VTC_FLOW);
	encap_hdr->ip.proto = IPPROTO_UDP;
	encap_hdr->ip.hop_limits = 50;
	encap_hdr->udp.src_port = 0x0; // computed
	encap_hdr->udp.dst_port = RTE_BE16(DOCA_FLOW_PSP_DEFAULT_PORT);
	encap_hdr->psp.nexthdr = 4;
	encap_hdr->psp.hdrextlen = (uint8_t)(app_config->net_config.vc_enabled ? 2 : 1);
	encap_hdr->psp.res_cryptofst = (uint8_t)app_config->net_config.crypt_offset;
	encap_hdr->psp.spi = RTE_BE32(spi);
	// encap_hdr->psp_virt_cookie = RTE_BE64(session->vc);
	encap_hdr->psp_virt_cookie = 0x778899aabbccddee;

	encap_hdr->psp.rsrv1 = 1; // always 1
	encap_hdr->psp.ver = app_config->net_config.default_psp_proto_ver;
	encap_hdr->psp.v = !!app_config->net_config.vc_enabled;
	// encap_hdr->psp.s will be set by the egress_sampling pipe

	memcpy(encap_hdr->eth.src_addr.addr_bytes, pf_dev.pf_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
	memcpy(encap_hdr->eth.dst_addr.addr_bytes, &nic_info.nexthop_mac, RTE_ETHER_ADDR_LEN);
	memcpy(encap_hdr->ip.src_addr, pf_dev.local_pip.ipv6_addr, IPV6_ADDR_LEN);

	if (inet_pton(AF_INET6, session.remote_pip.c_str(), &encap_hdr->ip.dst_addr) != 1) {
		DOCA_LOG_ERR("Failed to convert remote_vip %s to IPv6", session.remote_pip.c_str());
		return;
	}
}

void PSP_GatewayFlows::format_encap_data_ipv4(const psp_session_desc_t &session, uint32_t spi, uint8_t *encap_data)
{
	auto *encap_hdr = (eth_ipv4_psp_tunnel_hdr *)encap_data;

	encap_hdr->eth.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	encap_hdr->udp.src_port = 0x0; // computed
	encap_hdr->udp.dst_port = RTE_BE16(DOCA_FLOW_PSP_DEFAULT_PORT);
	encap_hdr->psp.nexthdr = 4;
	encap_hdr->psp.hdrextlen = (uint8_t)(app_config->net_config.vc_enabled ? 2 : 1);
	encap_hdr->psp.res_cryptofst = (uint8_t)app_config->net_config.crypt_offset;
	encap_hdr->psp.spi = RTE_BE32(spi);
	// encap_hdr->psp_virt_cookie = RTE_BE64(session->vc);
	encap_hdr->psp_virt_cookie = 0x778899aabbccddee;

	memcpy(encap_hdr->eth.src_addr.addr_bytes, pf_dev.pf_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
	memcpy(encap_hdr->eth.dst_addr.addr_bytes, &nic_info.nexthop_mac, RTE_ETHER_ADDR_LEN);
	encap_hdr->ip.src_addr = pf_dev.local_pip.ipv4_addr;
	encap_hdr->ip.version_ihl = 0x45;
	encap_hdr->ip.next_proto_id = IPPROTO_UDP;

	encap_hdr->psp.rsrv1 = 1; // always 1
	encap_hdr->psp.ver = app_config->net_config.default_psp_proto_ver;
	encap_hdr->psp.v = !!app_config->net_config.vc_enabled;
	// encap_hdr->psp.s will be set by the egress_sampling pipe

	if (inet_pton(AF_INET, session.remote_pip.c_str(), &encap_hdr->ip.dst_addr) != 1) {
		DOCA_LOG_ERR("Failed to convert remote_vip %s to IPv4", session.remote_pip.c_str());
		return;
	}
}

doca_error_t PSP_GatewayFlows::config_encrypt_entry(const psp_session_desc_t &session, uint32_t spi, uint32_t crypto_id, doca_flow_pipe_entry **entry)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	doca_error_t result = DOCA_SUCCESS;

	bool ipv6_pip = session.remote_pip.find(":") != std::string::npos;
	// If we receive a non-NULL entry, instead of creating a new entry, we just update the old one in-place
	bool update_entry = *entry != NULL;

	DOCA_LOG_INFO("%s encrypt flow entry: dst_pip %s, dst_vip %s, SPI %d, crypto_id %d",
			update_entry ? "Updating" : "Adding",
		     session.remote_pip.c_str(),
		     session.remote_vip.c_str(),
		     spi,
		     crypto_id);

	doca_flow_match encap_encrypt_match = {};
	encap_encrypt_match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	encap_encrypt_match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	if (inet_pton(AF_INET, session.remote_vip.c_str(), &encap_encrypt_match.outer.ip4.dst_ip) != 1) {
		DOCA_LOG_ERR("Failed to convert remote_vip %s to IPv4", session.remote_vip.c_str());
		return DOCA_ERROR_BAD_STATE;
	}
	if (inet_pton(AF_INET, session.local_vip.c_str(), &encap_encrypt_match.outer.ip4.src_ip) != 1) {
		DOCA_LOG_ERR("Failed to convert local_vip %s to IPv4", session.local_vip.c_str());
		return DOCA_ERROR_BAD_STATE;
	}

	doca_flow_actions encap_actions = {};
	encap_actions.has_crypto_encap = true;
	encap_actions.crypto_encap.action_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP;
	encap_actions.crypto_encap.net_type = DOCA_FLOW_CRYPTO_HEADER_PSP_TUNNEL;
	encap_actions.crypto_encap.icv_size = PSP_ICV_SIZE;

	if (ipv6_pip) {
		encap_actions.crypto_encap.data_size = sizeof(eth_ipv6_psp_tunnel_hdr);
		encap_actions.action_idx = 0;
	} else {
		encap_actions.crypto_encap.data_size = sizeof(eth_ipv4_psp_tunnel_hdr);
		encap_actions.action_idx = 1;
	}

	if (!app_config->net_config.vc_enabled) {
		encap_actions.crypto_encap.data_size -= sizeof(uint64_t);
	}
	if (ipv6_pip)
		format_encap_data_ipv6(session, spi, encap_actions.crypto_encap.encap_data);
	else
		format_encap_data_ipv4(session, spi, encap_actions.crypto_encap.encap_data);

	encap_actions.crypto.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT;
	encap_actions.crypto.resource_type = DOCA_FLOW_CRYPTO_RESOURCE_PSP;
	encap_actions.crypto.crypto_id = crypto_id;

	if (update_entry) {
		result = update_single_entry(0,
						egress_acl_pipe,
						&encap_encrypt_match,
						&encap_actions,
						nullptr,
						nullptr,
						*entry);
	}
	else {
		result = add_single_entry(0,
					egress_acl_pipe,
					pf_dev.pf_port,
					&encap_encrypt_match,
					&encap_actions,
					nullptr,
					nullptr,
					entry);
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add encrypt_encap pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	return result;
}

doca_error_t PSP_GatewayFlows::add_ingress_acl_entry(const psp_session_desc_t &session, uint32_t spi, doca_flow_pipe_entry **entry)
{
	if (app_config->disable_ingress_acl) {
		DOCA_LOG_WARN("Cannot insert ingress ACL flow; disabled");
		return DOCA_SUCCESS;
	}

	doca_flow_match match = {};
	match.parser_meta.psp_syndrome = 0;
	match.tun.type = DOCA_FLOW_TUN_PSP;
	match.tun.psp.spi = RTE_BE32(spi);
	match.inner.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	if (inet_pton(AF_INET, session.remote_vip.c_str(), &match.inner.ip4.src_ip) != 1) {
		DOCA_LOG_ERR("Failed to convert remote_vip %s to IPv4", session.remote_vip.c_str());
		return DOCA_ERROR_BAD_STATE;
	}

	doca_error_t result = DOCA_SUCCESS;
	IF_SUCCESS(result,
		   add_single_entry(0,
				    ingress_acl_pipe,
				    pf_dev.pf_port,
				    &match,
				    nullptr,
				    nullptr,
				    nullptr,
				    entry));

	return result;
}

doca_error_t PSP_GatewayFlows::remove_single_entry(doca_flow_pipe_entry *entry)
{
	doca_error_t result = DOCA_SUCCESS;
	assert(entry);

	result = doca_flow_pipe_remove_entry(0, DOCA_FLOW_NO_WAIT, entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_INFO("Error removing entry from SW: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_entries_process(pf_dev.pf_port, 0, DEFAULT_TIMEOUT_US, 1);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Error removing entry from HW: %s", doca_error_get_descr(result));
	}
	return result;
}

struct PSP_GatewayFlows::pipe_query {
	doca_flow_pipe *pipe;	     // used to query misses
	doca_flow_pipe_entry *entry; // used to query static entries
	std::string name;	     // displays the pipe name
};

std::pair<uint64_t, uint64_t> PSP_GatewayFlows::perform_pipe_query(pipe_query *query, bool suppress_output)
{
	uint64_t new_hits = 0;
	uint64_t new_misses = 0;

	if (query->entry) {
		doca_flow_resource_query stats = {};
		doca_error_t result = doca_flow_resource_query_entry(query->entry, &stats);
		if (result == DOCA_SUCCESS) {
			new_hits = stats.counter.total_pkts;
		}
	}
	if (query->pipe) {
		doca_flow_resource_query stats = {};
		doca_error_t result = doca_flow_resource_query_pipe_miss(query->pipe, &stats);
		if (result == DOCA_SUCCESS) {
			new_misses = stats.counter.total_pkts;
		}
	}
	if (!suppress_output) {
		if (query->entry && query->pipe) {
			DOCA_LOG_INFO("%s: %ld hits %ld misses", query->name.c_str(), new_hits, new_misses);
		} else if (query->entry) {
			DOCA_LOG_INFO("%s: %ld hits", query->name.c_str(), new_hits);
		} else if (query->pipe) {
			DOCA_LOG_INFO("%s: %ld misses", query->name.c_str(), new_hits);
		}
	}

	return std::make_pair(new_hits, new_misses);
}

void PSP_GatewayFlows::show_static_flow_counts(void)
{
	std::vector<pipe_query> queries;
	queries.emplace_back(pipe_query{nullptr, default_rss_entry_ingress, "rss_pipe_ingress"});
	queries.emplace_back(pipe_query{nullptr, default_rss_entry_egress, "rss_pipe_egress"});
	queries.emplace_back(pipe_query{nullptr, root_jump_to_ingress_ipv6_entry, "root_jump_to_ingress_ipv6_entry"});
	queries.emplace_back(pipe_query{nullptr, root_jump_to_ingress_ipv4_entry, "root_jump_to_ingress_ipv4_entry"});
	queries.emplace_back(pipe_query{nullptr, root_jump_to_egress_entry, "root_jump_to_egress_entry"});
	queries.emplace_back(pipe_query{nullptr, root_default_drop, "root_miss_drop"});
	queries.emplace_back(pipe_query{ingress_decrypt_pipe, default_decrypt_entry, "ingress_decrypt_pipe"});
	queries.emplace_back(pipe_query{ingress_sampling_pipe, default_ingr_sampling_entry, "ingress_sampling_pipe"});
	queries.emplace_back(pipe_query{ingress_acl_pipe, default_ingr_acl_entry, "ingress_acl_pipe"});
	for (int i = 0; i < NUM_OF_PSP_SYNDROMES; i++) {
		queries.emplace_back(
			pipe_query{nullptr, syndrome_stats_entries[i], "syndrome[" + std::to_string(i) + "]"});
	}
	queries.emplace_back(pipe_query{empty_pipe, nullptr, "egress_root"});
	queries.emplace_back(pipe_query{egress_acl_pipe, nullptr, "egress_acl_pipe"});
	queries.emplace_back(pipe_query{egress_sampling_pipe, default_egr_sampling_entry, "egress_sampling_pipe"});
	queries.emplace_back(pipe_query{nullptr, empty_pipe_entry, "arp_packets_intercepted"});

	uint64_t total_pkts = 0;
	for (auto &query : queries) {
		auto hits_misses = perform_pipe_query(&query, true);
		total_pkts += hits_misses.first + hits_misses.second;
	}

	if (total_pkts != prev_static_flow_count) {
		total_pkts = 0;
		DOCA_LOG_INFO("%s -------------------------", nic_info.pci.c_str());
		for (auto &query : queries) {
			auto hits_misses = perform_pipe_query(&query, false);
			total_pkts += hits_misses.first + hits_misses.second;
		}
		prev_static_flow_count = total_pkts;
	}
}

void PSP_GatewayFlows::show_session_flow_counts(void)
{
	for (auto &session : egress_sessions) {
		doca_flow_resource_query stats = {};
		doca_error_t result = doca_flow_resource_query_entry(session.second.encap_encrypt_entry, &stats);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_WARN("Session Egress flow %s->%s: query failed: %s",
				      session.first.local_vip.c_str(),
				      session.first.remote_vip.c_str(),
				      doca_error_get_descr(result));
			continue;
		}
		if (session.second.pkt_count_egress != stats.counter.total_pkts) {
			DOCA_LOG_INFO("Session Egress flow %s->%s: %ld hits",
					session.first.local_vip.c_str(),
					session.first.remote_vip.c_str(),
					stats.counter.total_pkts);
			session.second.pkt_count_egress = stats.counter.total_pkts;
		}
	}

	if (!app_config->disable_ingress_acl) {
		for (auto &session : ingress_sessions) {
			doca_flow_resource_query stats = {};
			doca_error_t result = doca_flow_resource_query_entry(session.second.ingress_acl_entry, &stats);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_WARN("Session Ingress flow %s<-%s: query failed: %s",
					session.first.local_vip.c_str(),
					session.first.remote_vip.c_str(),
					doca_error_get_descr(result));
				continue;
			}
			if (session.second.pkt_count_ingress != stats.counter.total_pkts) {
				DOCA_LOG_INFO("Session Ingress flow %s<-%s: %ld hits",
					session.first.local_vip.c_str(),
					session.first.remote_vip.c_str(),
					stats.counter.total_pkts);
				session.second.pkt_count_ingress = stats.counter.total_pkts;
			}
		}
	}
}
