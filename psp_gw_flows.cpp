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

#include <string>
#include <vector>

#include <doca_flow.h>
#include <doca_flow_crypto.h>
#include <doca_log.h>
#include <rte_psp.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#include "psp_gw_config.h"
#include "psp_gw_flows.h"
#include "psp_gw_utils.h"

DOCA_LOG_REGISTER(PSP_GATEWAY);

static const uint32_t DEFAULT_TIMEOUT_US = 10000; /* default timeout for processing entries */
static const uint32_t PSP_ICV_SIZE = 16;
static const uint32_t DUMMY_CRYPTO_ID = 1; // for pipe creation

/**
 * @brief user context struct that will be used in entries process callback
 */
struct entries_status {
	bool failure;	      /* will be set to true if some entry status will not be success */
	int nb_processed;     /* number of entries that was already processed */
	int entries_in_queue; /* number of entries in queue that is waiting to process */
};

/**
 * @brief packet header structure to simplify populating the encap_data array
 */
struct eth_ipv6_psp_tunnel_hdr {
	// encapped Ethernet header contents.
	struct doca_flow_header_eth eth;

	// encapped IP header contents (extension header not supported)
	struct rte_ipv6_hdr ip;

	struct rte_udp_hdr udp;

	// encapped PSP header contents.
	struct rte_psp_base_hdr psp;
	rte_be64_t psp_virt_cookie;

} __rte_packed __rte_aligned(2);

uint8_t PSP_SAMPLE_ENABLE = (rte_psp_base_hdr){.s = 1}.s_d_ver_v_1;

struct doca_flow_monitor monitor_count = {
	.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
};

PSP_GatewayFlows::PSP_GatewayFlows(struct psp_pf_dev *pf, uint16_t vf_port_id, psp_gw_app_config *app_config)
	: app_config(app_config),
	  pf_dev(pf),
	  vf_port_id(vf_port_id)
{
}

PSP_GatewayFlows::~PSP_GatewayFlows()
{
	if (vf_port)
		doca_flow_port_stop(vf_port);
	if (pf_dev->port_obj)
		doca_flow_port_stop(pf_dev->port_obj);
	doca_flow_destroy();
}

doca_error_t PSP_GatewayFlows::init(void)
{
	doca_error_t result;

	result = init_doca_flow(app_config);
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = start_port(pf_dev->port_id, pf_dev->dev, &pf_dev->port_obj);
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = start_port(vf_port_id, NULL, &vf_port);
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = bind_shared_resources();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = rss_pipe_create();
	if (result != DOCA_SUCCESS)
		return result;

	result = configure_mirrors();
	if (result != DOCA_SUCCESS)
		return result;

	result = create_pipes();
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

doca_error_t PSP_GatewayFlows::configure_mirrors(void)
{
	doca_error_t result;
	doca_flow_mirror_target mirr_tgt = {
		.fwd =
			{
				.type = DOCA_FLOW_FWD_PIPE,
				.next_pipe = rss_pipe,
			},
	};
	struct doca_flow_shared_resource_cfg res_cfg = {
		.mirror_cfg =
			{
				.nr_targets = 1,
				.target = &mirr_tgt,
			},
	};

	res_cfg.domain = DOCA_FLOW_PIPE_DOMAIN_DEFAULT;
	result = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_MIRROR, ingress_mirror_id, &res_cfg);
	if (result != DOCA_SUCCESS)
		return result;

	res_cfg.domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS;
	result = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_MIRROR, egress_mirror_id, &res_cfg);
	if (result != DOCA_SUCCESS)
		return result;

	std::vector<uint32_t> mirror_ids = {ingress_mirror_id, egress_mirror_id};
	result = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_MIRROR,
						 mirror_ids.data(),
						 (uint32_t)mirror_ids.size(),
						 pf_dev->port_obj);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to bind %ld mirror shared resources: %s",
			     mirror_ids.size(),
			     doca_error_get_descr(result));
	}
	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::start_port(uint16_t port_id, struct doca_dev *port_dev, struct doca_flow_port **port)
{
	std::string port_id_str = std::to_string(port_id);

	struct doca_flow_port_cfg port_cfg = {
		.port_id = port_id,
		.type = DOCA_FLOW_PORT_DPDK_BY_ID,
		.devargs = port_id_str.c_str(),
		.dev = port_dev,
	};

	doca_error_t result = doca_flow_port_start(&port_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow port %d: %s", port_id, doca_error_get_descr(result));
		return result;
	}

	rte_ether_addr port_mac_addr;
	rte_eth_macaddr_get(port_id, &port_mac_addr);
	DOCA_LOG_INFO("Started port_id %d, mac-addr: %s", port_id, mac_to_string(port_mac_addr).c_str());

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::init_doca_flow(const struct psp_gw_app_config *app_cfg)
{
	static const int QUEUE_DEPTH = 512;

	uint16_t nb_queues = app_cfg->dpdk_config.port_config.nb_queues;

	uint16_t rss_queues[nb_queues];
	for (int i = 0; i < nb_queues; i++)
		rss_queues[i] = i;

	/* init doca flow with crypto shared resources */
	struct doca_flow_cfg flow_cfg = {
		.pipe_queues = nb_queues,
		.resource =
			{
				.nb_counters = app_cfg->max_tunnels * NUM_OF_PSP_SYNDROMES + 10,
			},
		.mode_args = "switch,hws,isolated",
		.queue_depth = QUEUE_DEPTH,
		.cb = PSP_GatewayFlows::check_for_valid_entry,
		.rss =
			{
				.queues_array = rss_queues,
				.nr_queues = nb_queues,
			},
	};
	flow_cfg.nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_PSP] = app_cfg->max_tunnels + 1;
	flow_cfg.nr_shared_resources[DOCA_FLOW_SHARED_RESOURCE_MIRROR] = 3;

	doca_error_t result = doca_flow_init(&flow_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return result;
	}
	DOCA_LOG_INFO("Initialized DOCA Flow for a max of %d tunnels", app_cfg->max_tunnels);
	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::bind_shared_resources(void)
{
	doca_error_t result;

	std::vector<uint32_t> psp_ids(app_config->max_tunnels);
	for (uint32_t i = 0; i < app_config->max_tunnels; i++) {
		psp_ids[i] = i + 1;
	}

	result = doca_flow_shared_resources_bind(DOCA_FLOW_SHARED_RESOURCE_PSP,
						 psp_ids.data(),
						 app_config->max_tunnels,
						 pf_dev->port_obj);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to bind %d PSP shared resources: %s",
			     app_config->max_tunnels,
			     doca_error_get_descr(result));
	}

	// Mirror configurations performed when creating the pipes
	ingress_mirror_id = 1;
	egress_mirror_id = 2;

	return result;
}

doca_error_t PSP_GatewayFlows::create_pipes(void)
{
	doca_error_t result;

	result = syndrome_stats_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = ingress_acl_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = ingress_sampling_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = ingress_decrypt_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = egress_encrypt_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = egress_sampling_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = egress_acl_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	result = ingress_root_pipe_create();
	if (result != DOCA_SUCCESS) {
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::rss_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	doca_error_t result;

	doca_flow_match null_match = {};
	doca_flow_pipe_cfg rss_pipe_cfg = {
		.attr =
			{
				.name = "RSS_PIPE",
				.is_root = true, // special case
				.nb_flows = 1,
			},
		.port = pf_dev->port_obj,
		.match = &null_match,
		.match_mask = &null_match,
		.monitor = &monitor_count,
	};

	// Note packets sent to RSS will be processed by lcore_pkt_proc_func().
	uint16_t rss_queues[1] = {0};
	doca_flow_fwd fwd_rss = {};
	fwd_rss.type = DOCA_FLOW_FWD_RSS;
	fwd_rss.rss_outer_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_IPV6;
	fwd_rss.rss_queues = rss_queues;
	fwd_rss.num_of_queues = 1;
	result = doca_flow_pipe_create(&rss_pipe_cfg, &fwd_rss, NULL, &rss_pipe);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE, "Failed to create RSS pipe: %d (%s)\n", result, doca_error_get_descr(result));
	}

	result = add_single_entry(0, rss_pipe, pf_dev->port_obj, &null_match, NULL, NULL, NULL, &default_rss_entry);
	if (result != DOCA_SUCCESS) {
		rte_exit(EXIT_FAILURE,
			 "Failed to add default entry to RSS pipe: %d (%s)\n",
			 result,
			 doca_error_get_descr(result));
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::ingress_decrypt_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(ingress_sampling_pipe);
	assert(rss_pipe);

	doca_flow_match match = {
		.parser_meta =
			{
				.port_meta = UINT32_MAX,
				.outer_l3_type = DOCA_FLOW_L3_META_IPV6,
				.outer_l4_type = DOCA_FLOW_L4_META_UDP,
			},
		.outer =
			{
				.l3_type = DOCA_FLOW_L3_TYPE_IP6,
				.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_UDP,
				.udp =
					{
						.l4_port =
							{
								.dst_port = RTE_BE16(DOCA_FLOW_PSP_DEFAULT_PORT),
							},
					},
			},
		.tun =
			{
				.type = DOCA_FLOW_TUN_PSP,
			},
	};

	doca_flow_actions actions = {
		.crypto =
			{
				.action_type = DOCA_FLOW_CRYPTO_ACTION_DECRYPT,
				.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_PSP,
				.crypto_id = DOCA_FLOW_PSP_DECRYPTION_ID,
			},
	};
	doca_flow_actions *actions_arr[] = {&actions};

	doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = ingress_sampling_pipe,
	};
	doca_flow_fwd fwd_miss = {
		.type = DOCA_FLOW_FWD_DROP,
	};

	doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "PSP_DECRYPT",
				.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS,
				.nb_flows = 1,
				.enable_strict_matching = true,
				.nb_actions = 1,
				.dir_info = DOCA_FLOW_DIRECTION_NETWORK_TO_HOST,
				.miss_counter = true,
			},
		.port = pf_dev->port_obj,
		.match = &match,
		.actions = actions_arr,
		.monitor = &monitor_count,
	};

	doca_error_t result = doca_flow_pipe_create(&cfg, &fwd, &fwd_miss, &ingress_decrypt_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	doca_flow_match match_uplink = {
		.parser_meta =
			{
				.port_meta = 0,
			},
	};
	result = add_single_entry(0,
				  ingress_decrypt_pipe,
				  pf_dev->port_obj,
				  &match_uplink,
				  &actions,
				  NULL,
				  NULL,
				  &default_decrypt_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add default entry to %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::ingress_sampling_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(ingress_mirror_id);
	assert(ingress_acl_pipe);
	assert(rss_pipe);

	doca_error_t result;

	doca_flow_match match_psp_sampling_bit = {
		.tun =
			{
				.type = DOCA_FLOW_TUN_PSP,
				.psp =
					{
						.s_d_ver_v = PSP_SAMPLE_ENABLE,
					},
			},
	};

	doca_flow_monitor mirror_action = {
		.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED,
		.shared_mirror_id = ingress_mirror_id,
	};

	doca_flow_actions set_meta = {
		.meta =
			{
				.pkt_meta = app_config->sample_meta_indicator,
			},
	};
	doca_flow_actions *actions_arr[] = {&set_meta};

	doca_flow_actions set_meta_mask = {
		.meta =
			{
				.pkt_meta = UINT32_MAX,
			},
	};
	doca_flow_actions *actions_masks_arr[] = {&set_meta_mask};

	doca_flow_fwd fwd_and_miss = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = ingress_acl_pipe,
	};

	doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "INGR_SAMPL",
				.nb_flows = 1,
				.enable_strict_matching = true,
				.nb_actions = 1,
				.miss_counter = true,
			},
		.port = pf_dev->port_obj,
		.match = &match_psp_sampling_bit,
		.match_mask = &match_psp_sampling_bit,
		.actions = actions_arr,
		.actions_masks = actions_masks_arr,
		.monitor = &mirror_action,
	};

	result = doca_flow_pipe_create(&cfg, &fwd_and_miss, &fwd_and_miss, &ingress_sampling_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	result = add_single_entry(0,
				  ingress_sampling_pipe,
				  pf_dev->port_obj,
				  NULL,
				  NULL,
				  NULL,
				  NULL,
				  &default_ingr_sampling_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add default entry to %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::ingress_acl_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	struct doca_flow_match match = {
		.parser_meta =
			{
				.psp_syndrome = UINT8_MAX,
			},
		.tun =
			{
				.type = DOCA_FLOW_TUN_PSP,
			},
		// src/dst addr could be matched here for robust ACL
	};

	struct doca_flow_actions actions = {
		.has_crypto_encap = true,
		.crypto_encap =
			{
				.action_type = DOCA_FLOW_CRYPTO_REFORMAT_DECAP,
				.net_type = DOCA_FLOW_CRYPTO_HEADER_PSP_TUNNEL,
				.icv_size = PSP_ICV_SIZE,
				.data_size = sizeof(rte_ether_hdr),
			},
	};
	rte_ether_hdr *eth_hdr = (rte_ether_hdr *)actions.crypto_encap.encap_data;
	eth_hdr->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
	eth_hdr->src_addr = pf_dev->src_mac;
	rte_eth_macaddr_get(vf_port_id, &eth_hdr->dst_addr);

	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = vf_port_id,
	};

	struct doca_flow_fwd fwd_miss = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = syndrome_stats_pipe,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "INGR_ACL",
				.nb_flows = 1,
				.enable_strict_matching = true,
				.nb_actions = 1,
				.dir_info = DOCA_FLOW_DIRECTION_NETWORK_TO_HOST,
				.miss_counter = true, // count packets with bad syndrome
			},
		.port = pf_dev->port_obj,
		.match = &match,
		.actions = actions_arr,
		.monitor = &monitor_count,
	};

	doca_error_t result = doca_flow_pipe_create(&cfg, &fwd, &fwd_miss, &ingress_acl_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	struct doca_flow_match match_uplink = {
		.parser_meta =
			{
				.port_meta = 0,
			},
	};
	result = add_single_entry(0,
				  ingress_acl_pipe,
				  pf_dev->port_obj,
				  &match_uplink,
				  &actions,
				  NULL,
				  NULL,
				  &default_ingr_acl_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add default entry to %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::syndrome_stats_pipe_create(void)
{
	doca_error_t result;

	doca_flow_match syndrome_match = {
		.parser_meta =
			{
				.psp_syndrome = 0xff,
			},
	};
	// If we got here, the packet failed either the PSP decryption syndrome check
	// or the ACL check. Whether the syndrome bits match here or not, the
	// fate of the packet is to drop.
	doca_flow_fwd fwd_drop = {
		.type = DOCA_FLOW_FWD_DROP,
	};
	doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "SYNDROME_STATS",
				.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS,
				.nb_flows = NUM_OF_PSP_SYNDROMES,
				.dir_info = DOCA_FLOW_DIRECTION_NETWORK_TO_HOST,
				.miss_counter = true,
			},
		.port = pf_dev->port_obj,
		.match = &syndrome_match,
		.monitor = &monitor_count,
	};

	result = doca_flow_pipe_create(&cfg, &fwd_drop, &fwd_drop, &syndrome_stats_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	for (int i = 0; i < NUM_OF_PSP_SYNDROMES; i++) {
		syndrome_match.parser_meta.psp_syndrome = 1 << i;
		add_single_entry(0,
				 syndrome_stats_pipe,
				 pf_dev->port_obj,
				 &syndrome_match,
				 NULL,
				 &monitor_count,
				 NULL,
				 &syndrome_stats_entries[i]);
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::egress_acl_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(egress_sampling_pipe);
	assert(rss_pipe);

	struct doca_flow_match match = {
		.parser_meta =
			{
				.outer_l3_type = DOCA_FLOW_L3_META_IPV4,
			},
		.outer =
			{
				.l3_type = DOCA_FLOW_L3_TYPE_IP4,
				.ip4 =
					{
						.dst_ip = UINT32_MAX,
					},
			},
	};

	struct doca_flow_actions actions = {
		.meta =
			{
				.pkt_meta = UINT32_MAX, // hold the crypto_id until the packet reaches the encrypt pipe
			},
		.has_crypto_encap = true,
		.crypto_encap =
			{
				.action_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP,
				.net_type = DOCA_FLOW_CRYPTO_HEADER_PSP_TUNNEL,
				.icv_size = PSP_ICV_SIZE,
				.data_size = sizeof(eth_ipv6_psp_tunnel_hdr),
			},
	};
	if (!app_config->net_config.vc_enabled) {
		actions.crypto_encap.data_size -= sizeof(uint64_t);
	}
	memset(actions.crypto_encap.encap_data, 0xff, actions.crypto_encap.data_size);

	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = egress_sampling_pipe,
	};

	struct doca_flow_fwd fwd_miss = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = rss_pipe,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "EGR_ACL",
				.domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS,
				.is_root = true,
				.nb_flows = app_config->max_tunnels,
				.nb_actions = 1,
				.dir_info = DOCA_FLOW_DIRECTION_HOST_TO_NETWORK,
				.miss_counter = true,
			},
		.port = pf_dev->port_obj,
		.match = &match,
		.actions = actions_arr,
		.monitor = &monitor_count,
	};
	doca_error_t result = doca_flow_pipe_create(&cfg, &fwd, &fwd_miss, &egress_acl_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::add_encrypt_entry(struct psp_session_t *session, const void *encrypt_key)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	doca_error_t result;
	std::string dst_pip = ipv6_to_string(session->dst_pip);
	std::string dst_vip = ipv4_to_string(session->dst_vip);

	DOCA_LOG_INFO("Creating encrypt flow entry: dst_pip %s, dst_vip %s, SPI %d, crypto_id %d",
		      dst_pip.c_str(),
		      dst_vip.c_str(),
		      session->spi,
		      session->crypto_id);

	struct doca_flow_shared_resource_cfg res_cfg = {
		.psp_cfg =
			{
				.key_cfg =
					{
						.key_type = DOCA_FLOW_CRYPTO_KEY_256,
						.key = (uint32_t *)encrypt_key,
					},
			},
	};
	result = doca_flow_shared_resource_cfg(DOCA_FLOW_SHARED_RESOURCE_PSP, session->crypto_id, &res_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to configure crypto_id %d: %s", session->crypto_id, doca_error_get_descr(result));
		return result;
	}

	struct doca_flow_match encap_match = {
		.parser_meta =
			{
				.outer_l3_type = DOCA_FLOW_L3_META_IPV4,
			},
		.outer =
			{
				.l3_type = DOCA_FLOW_L3_TYPE_IP4,
				.ip4 =
					{
						.dst_ip = session->dst_vip,
					},
			},
	};

	struct doca_flow_actions encap_actions = {
		.meta =
			{
				.pkt_meta = session->crypto_id,
			},
		.has_crypto_encap = true,
		.crypto_encap =
			{
				.action_type = DOCA_FLOW_CRYPTO_REFORMAT_ENCAP,
				.net_type = DOCA_FLOW_CRYPTO_HEADER_PSP_TUNNEL,
				.icv_size = PSP_ICV_SIZE,
				.data_size = sizeof(eth_ipv6_psp_tunnel_hdr),
			},
	};
	if (!app_config->net_config.vc_enabled) {
		encap_actions.crypto_encap.data_size -= sizeof(uint64_t);
	}
	format_encap_data(session, encap_actions.crypto_encap.encap_data);

	result = add_single_entry(0,
				  egress_acl_pipe,
				  pf_dev->port_obj,
				  &encap_match,
				  &encap_actions,
				  NULL,
				  NULL,
				  &session->encap_entry);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add encrypt_encap pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	doca_flow_match encrypt_match = {
		.meta =
			{
				.pkt_meta = session->crypto_id,
			},
	};
	struct doca_flow_actions encrypt_actions = {
		.crypto =
			{
				.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT,
				.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_PSP,
				.crypto_id = session->crypto_id,
			},
	};
	result = add_single_entry(0,
				  egress_encrypt_pipe,
				  pf_dev->port_obj,
				  &encrypt_match,
				  &encrypt_actions,
				  NULL,
				  NULL,
				  &session->encrypt_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add encrypt entry to pipe: %s", doca_error_get_descr(result));

		doca_flow_pipe_rm_entry(0, DOCA_FLOW_NO_WAIT, session->encap_entry);
		doca_flow_entries_process(pf_dev->port_obj, 0, DEFAULT_TIMEOUT_US, 1);

		return result;
	}

	session->pkt_count = UINT64_MAX; // force next query to detect a change

	DOCA_LOG_DBG("Created session entries: %p, %p", session->encap_entry, session->encrypt_entry);

	return DOCA_SUCCESS;
}

void PSP_GatewayFlows::format_encap_data(const psp_session_t *session, uint8_t *encap_data)
{
	// Set the crypto_offset large enough to transmit
	// IP addresses unencrypted:
	size_t vc_size = app_config->net_config.vc_enabled ? sizeof(uint64_t) : 0;
	size_t ip_size = sizeof(rte_ipv4_hdr);			       // inner is always ipv4
	size_t crypto_offset = (vc_size + ip_size) / sizeof(uint32_t); // number of 32-bit words

	static const doca_be32_t DEFAULT_VTC_FLOW = 0x6 << 28;

	auto *encap_hdr = (eth_ipv6_psp_tunnel_hdr *)encap_data;
	*encap_hdr = (eth_ipv6_psp_tunnel_hdr){
		.eth =
			{
				.type = RTE_BE16(DOCA_ETHER_TYPE_IPV6),
			},
		.ip =
			{
				.vtc_flow = RTE_BE32(DEFAULT_VTC_FLOW),
				.proto = IPPROTO_UDP,
				.hop_limits = 50,
			},
		.udp =
			{
				.src_port = 0x0, // computed
				.dst_port = RTE_BE16(DOCA_FLOW_PSP_DEFAULT_PORT),
			},
		.psp =
			{
				.nexthdr = 4,
				.hdrextlen = (uint8_t)(app_config->net_config.vc_enabled ? 2 : 1),
				.res_cryptofst = (uint8_t)crypto_offset,
				.spi = RTE_BE32(session->spi),
			},
		.psp_virt_cookie = RTE_BE64(session->vc),
	};
	memcpy(encap_hdr->eth.src_mac, pf_dev->src_mac.addr_bytes, DOCA_ETHER_ADDR_LEN);
	memcpy(encap_hdr->eth.dst_mac, session->dst_mac.addr_bytes, DOCA_ETHER_ADDR_LEN);
	memcpy(encap_hdr->ip.src_addr, pf_dev->src_pip, IPV6_ADDR_LEN);
	memcpy(encap_hdr->ip.dst_addr, session->dst_pip, IPV6_ADDR_LEN);
	encap_hdr->psp.rsrv1 = 1; // always 1
	encap_hdr->psp.ver = SUPPORTED_PSP_VER;
	encap_hdr->psp.v = !!app_config->net_config.vc_enabled;
	// encap_hdr->psp.s will be set by the egress_sampling pipe
}

doca_error_t PSP_GatewayFlows::remove_encrypt_entry(psp_session_t *session)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	doca_error_t result;
	uint16_t pipe_queue = 0;
	uint32_t flags = DOCA_FLOW_NO_WAIT;
	uint32_t num_of_entries = 2;

	result = doca_flow_pipe_rm_entry(pipe_queue, flags, session->encap_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_INFO("Error removing PSP encap entry: %s", doca_error_get_descr(result));
	}

	result = doca_flow_pipe_rm_entry(pipe_queue, flags, session->encrypt_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_INFO("Error removing PSP encrypt entry: %s", doca_error_get_descr(result));
	}

	result = doca_flow_entries_process(pf_dev->port_obj, 0, DEFAULT_TIMEOUT_US, num_of_entries);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to process entry: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::egress_sampling_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(egress_mirror_id);

	doca_error_t result;

	uint16_t mask = (uint16_t)((1 << app_config->log2_sample_rate) - 1);
	doca_flow_match match_sampling_match_mask = {.parser_meta = {
							     .random = mask,
						     }};
	doca_flow_match match_sampling_match = {.parser_meta = {
							.random = 0x1,
						}};

	doca_flow_actions set_sample_bit = {
		.tun =
			{
				.type = DOCA_FLOW_TUN_PSP,
				.psp =
					{
						.s_d_ver_v = PSP_SAMPLE_ENABLE,
					},
			},
	};
	doca_flow_actions *actions_arr[] = {&set_sample_bit};

	doca_flow_fwd fwd_and_miss = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = egress_encrypt_pipe,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "EGR_SAMPL",
				.domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS,
				.nb_flows = 1,
				.nb_actions = 1,
				.miss_counter = true,
			},
		.port = pf_dev->port_obj,
		.match = &match_sampling_match,
		.match_mask = &match_sampling_match_mask,
		.actions = actions_arr,
		.actions_masks = actions_arr,
		.monitor = &monitor_count,
	};
	result = doca_flow_pipe_create(&cfg, &fwd_and_miss, &fwd_and_miss, &egress_sampling_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	result = add_single_entry(0,
				  egress_sampling_pipe,
				  pf_dev->port_obj,
				  NULL,
				  NULL,
				  NULL,
				  NULL,
				  &default_egr_sampling_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add default entry to %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::egress_encrypt_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	struct doca_flow_match match = {
		.meta =
			{
				.pkt_meta = UINT32_MAX,
			},
	};

	struct doca_flow_actions actions = {
		.crypto =
			{
				.action_type = DOCA_FLOW_CRYPTO_ACTION_ENCRYPT,
				.proto_type = DOCA_FLOW_CRYPTO_PROTOCOL_PSP,
				.crypto_id = UINT32_MAX, // per entry
			},
	};

	struct doca_flow_actions *actions_arr[] = {&actions};

	struct doca_flow_fwd fwd = {
		.type = DOCA_FLOW_FWD_PORT,
		.port_id = pf_dev->port_id,
	};

	struct doca_flow_fwd fwd_miss = {
		.type = DOCA_FLOW_FWD_DROP,
	};

	struct doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "PSP_ENCRYPT",
				.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_EGRESS,
				.nb_flows = app_config->max_tunnels,
				.nb_actions = 1,
				.dir_info = DOCA_FLOW_DIRECTION_HOST_TO_NETWORK,
				.miss_counter = true,
			},
		.port = pf_dev->port_obj,
		.match = &match,
		.match_mask = &match,
		.actions = actions_arr,
		.monitor = &monitor_count,
	};
	doca_error_t result = doca_flow_pipe_create(&cfg, &fwd, &fwd_miss, &egress_encrypt_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t PSP_GatewayFlows::ingress_root_pipe_create(void)
{
	DOCA_LOG_DBG("\n>> %s", __FUNCTION__);
	assert(ingress_decrypt_pipe);
	assert(egress_acl_pipe);

	doca_error_t result;

	doca_flow_pipe_cfg cfg = {
		.attr =
			{
				.name = "ROOT",
				.type = DOCA_FLOW_PIPE_CONTROL,
				.domain = DOCA_FLOW_PIPE_DOMAIN_SECURE_INGRESS,
				.is_root = true,
				.nb_flows = 3,
			},
		.port = pf_dev->port_obj,
	};

	result = doca_flow_pipe_create(&cfg, NULL, NULL, &ingress_root_pipe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create %s pipe: %s", cfg.attr.name, doca_error_get_descr(result));
		return result;
	}

	doca_flow_match mask = {
		.parser_meta =
			{
				.port_meta = UINT32_MAX,
				.outer_l3_ok = UINT8_MAX,
				.outer_ip4_checksum_ok = UINT8_MAX,
				.outer_l4_ok = UINT8_MAX,
			},
		.outer =
			{
				.eth =
					{
						.type = UINT16_MAX,
					},
			},
	};
	doca_flow_match ipv6_from_uplink = {.parser_meta =
						    {
							    .port_meta = pf_dev->port_id,
							    .outer_l3_ok = true,
							    .outer_ip4_checksum_ok = false,
							    .outer_l4_ok = true,
						    },
					    .outer = {
						    .eth =
							    {
								    .type = RTE_BE16(RTE_ETHER_TYPE_IPV6),
							    },
					    }};

	doca_flow_match ipv4_from_vf = {.parser_meta =
						{
							.port_meta = vf_port_id,
							.outer_l3_ok = true,
							.outer_ip4_checksum_ok = true,
							.outer_l4_ok = true,
						},
					.outer = {
						.eth =
							{
								.type = RTE_BE16(RTE_ETHER_TYPE_IPV4),
							},
					}};

	doca_flow_match arp_mask = {
		.parser_meta =
			{
				.port_meta = UINT32_MAX,
			},
		.outer =
			{
				.eth =
					{
						.type = UINT16_MAX,
					},
			},
	};
	doca_flow_match arp_from_vf = {.parser_meta =
					       {
						       .port_meta = vf_port_id,
					       },
				       .outer = {
					       .eth =
						       {
							       .type = RTE_BE16(RTE_ETHER_TYPE_ARP),
						       },
				       }};

	doca_flow_fwd fwd_ingress = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = ingress_decrypt_pipe,
	};
	doca_flow_fwd fwd_egress = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = egress_acl_pipe,
	};
	doca_flow_fwd fwd_rss = {
		.type = DOCA_FLOW_FWD_PIPE,
		.next_pipe = rss_pipe,
	};

	uint16_t pipe_queue = 0;
	doca_flow_pipe_entry *entry;

	result = doca_flow_pipe_control_add_entry(pipe_queue,
						  1,
						  ingress_root_pipe,
						  &ipv6_from_uplink,
						  &mask,
						  nullptr,
						  nullptr,
						  nullptr,
						  nullptr,
						  nullptr,
						  &fwd_ingress,
						  nullptr,
						  &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create root pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_pipe_control_add_entry(pipe_queue,
						  2,
						  ingress_root_pipe,
						  &ipv4_from_vf,
						  &mask,
						  nullptr,
						  nullptr,
						  nullptr,
						  nullptr,
						  nullptr,
						  &fwd_egress,
						  nullptr,
						  &entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create root pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_flow_pipe_control_add_entry(pipe_queue,
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
						  &vf_arp_to_rss);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create root pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
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
void PSP_GatewayFlows::check_for_valid_entry(struct doca_flow_pipe_entry *entry,
					     uint16_t pipe_queue,
					     enum doca_flow_entry_status status,
					     enum doca_flow_entry_op op,
					     void *user_ctx)
{
	(void)entry;
	(void)op;
	(void)pipe_queue;

	struct entries_status *entry_status = (struct entries_status *)user_ctx;

	if (entry_status == NULL || op != DOCA_FLOW_ENTRY_OP_ADD)
		return;

	if (status != DOCA_FLOW_ENTRY_STATUS_SUCCESS)
		entry_status->failure = true; /* set failure to true if processing failed */

	entry_status->nb_processed++;
	entry_status->entries_in_queue--;
}

doca_error_t PSP_GatewayFlows::add_single_entry(uint16_t pipe_queue,
						struct doca_flow_pipe *pipe,
						struct doca_flow_port *port,
						const struct doca_flow_match *match,
						const struct doca_flow_actions *actions,
						const struct doca_flow_monitor *mon,
						const struct doca_flow_fwd *fwd,
						struct doca_flow_pipe_entry **entry)
{
	int num_of_entries = 1;
	uint32_t flags = DOCA_FLOW_NO_WAIT;

	struct entries_status status = {.entries_in_queue = num_of_entries};
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

	return DOCA_SUCCESS;
}

void PSP_GatewayFlows::show_static_flow_counts(void)
{
	std::vector<std::pair<doca_flow_pipe_entry *, std::string>> entries{
		{default_rss_entry, "RSS"},
		{default_decrypt_entry, "Decrypt"},
		{default_ingr_sampling_entry, "IngrSampl"},
		{default_ingr_acl_entry, "ACL/Syndr"},
		{default_egr_sampling_entry, "EgrSampl"},
		//{vf_arp_to_rss, "VF ARP"},
	};
	for (int i = 0; i < NUM_OF_PSP_SYNDROMES; i++) {
		entries.push_back(std::make_pair(syndrome_stats_entries[i], "syndrome[" + std::to_string(i) + "]"));
	}

	std::vector<std::pair<doca_flow_pipe *, std::string>> pipes_with_miss_counter{
		{
			ingress_decrypt_pipe,
			"ingress_decrypt_pipe",
		},
		{
			ingress_sampling_pipe,
			"ingress_sampling_pipe",
		},
		{
			ingress_acl_pipe,
			"ingress_acl_pipe",
		},
		{
			egress_acl_pipe,
			"egress_acl_pipe",
		},
		{
			egress_sampling_pipe,
			"egress_sampling_pipe",
		},
		{
			egress_encrypt_pipe,
			"egress_encrypt_pipe",
		},
	};

	uint64_t total_hits = 0;
	for (auto &entry : entries) {
		if (!entry.first)
			continue;
		doca_flow_query stats = {};
		doca_error_t result = doca_flow_query_entry(entry.first, &stats);
		if (result == DOCA_SUCCESS) {
			total_hits += stats.total_pkts;
		}
	}
	for (auto &pipe : pipes_with_miss_counter) {
		doca_flow_query stats = {};
		doca_error_t result = doca_flow_query_pipe_miss(pipe.first, &stats);
		if (result == DOCA_SUCCESS) {
			total_hits += stats.total_pkts;
		}
	}

	if (total_hits != prev_static_flow_count) {
		DOCA_LOG_INFO("-------------------------");
		total_hits = 0;
		for (auto &entry : entries) {
			if (!entry.first)
				continue;
			doca_flow_query stats = {};
			doca_error_t result = doca_flow_query_entry(entry.first, &stats);
			if (result == DOCA_SUCCESS) {
				DOCA_LOG_INFO("Static flow %s: %ld hits", entry.second.c_str(), stats.total_pkts);

				total_hits += stats.total_pkts;
			} else {
				DOCA_LOG_INFO("Static flow %s: query failed: %s",
					      entry.second.c_str(),
					      doca_error_get_descr(result));
			}
		}
		for (auto &pipe : pipes_with_miss_counter) {
			doca_flow_query stats = {};
			doca_error_t result = doca_flow_query_pipe_miss(pipe.first, &stats);
			if (result == DOCA_SUCCESS) {
				DOCA_LOG_INFO("Pipe Miss %s: %ld hits", pipe.second.c_str(), stats.total_pkts);

				total_hits += stats.total_pkts;
			} else {
				DOCA_LOG_INFO("Pipe miss %s: query failed: %s",
					      pipe.second.c_str(),
					      doca_error_get_descr(result));
			}
		}
		prev_static_flow_count = total_hits;
	}
}

void PSP_GatewayFlows::show_session_flow_count(const std::string &dst_vip, psp_session_t &session)
{
	doca_flow_query encap_stats = {};
	doca_error_t encap_result = doca_flow_query_entry(session.encap_entry, &encap_stats);

	doca_flow_query encrypt_stats = {};
	doca_error_t encrypt_result = doca_flow_query_entry(session.encrypt_entry, &encrypt_stats);

	if (encap_result == DOCA_SUCCESS) {
		if (session.pkt_count != encap_stats.total_pkts) {
			DOCA_LOG_DBG("Session entries: %p, %p", session.encap_entry, session.encrypt_entry);
			DOCA_LOG_INFO("Session flow %s: %ld hits", dst_vip.c_str(), encap_stats.total_pkts);
			session.pkt_count = encap_stats.total_pkts;

			if (encrypt_result != DOCA_SUCCESS) {
				DOCA_LOG_WARN("Failed to query encrypt entry (encap entry succeded)");
			}
			if (encap_stats.total_pkts != encrypt_stats.total_pkts) {
				DOCA_LOG_WARN("Encap/Encrypt mismatch: %ld vs %ld",
					      encap_stats.total_pkts,
					      encrypt_stats.total_pkts);
			}
		}
	} else {
		DOCA_LOG_INFO("Session flow %s: query failed: %s", dst_vip.c_str(), doca_error_get_descr(encap_result));
	}
}
