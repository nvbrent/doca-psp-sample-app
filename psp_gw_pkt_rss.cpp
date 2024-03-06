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

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <doca_log.h>

#include <psp_gw_config.h>
#include <psp_gw_pkt_rss.h>
#include <psp_gw_svc_impl.h>

DOCA_LOG_REGISTER(PSP_RSS);

#define MAX_RX_BURST_SIZE 256

static uint16_t max_tx_retries = 10;

/**
 * @brief High-level Rx Queue packet handler routine
 * Optionally logs the packet to the console.
 * Passes the packet to the PSP Service so it can decide whether to
 * negotiate a new tunnel.
 *
 * @params [in]: the parameters to the lcore routines
 * @port_id [in]: the port_id from which the packet was received
 * @queue_id [in]: the queue index from which the packet was received
 * @packet [in]: the received packet buffer
 */
static void handle_packet(struct lcore_params *params, uint16_t port_id, uint16_t queue_id, struct rte_mbuf *packet)
{
	uint32_t pkt_meta = rte_flow_dynf_metadata_get(packet);
	if (pkt_meta == params->config->sample_meta_indicator) {
		printf("SAMPLED PACKET: port %d, queue_id %d, pkt_meta 0x%x\n", port_id, queue_id, pkt_meta);
		rte_pktmbuf_dump(stdout, packet, packet->data_len);
	} else if (params->config->show_rss_rx_packets) {
		printf("RSS: Received port %d, queue_id %d, pkt_meta 0x%x\n", port_id, queue_id, pkt_meta);
		rte_pktmbuf_dump(stdout, packet, packet->data_len);
	}

	params->psp_svc->handle_miss_packet(packet);
}

int lcore_pkt_proc_func(void *lcore_args)
{
	auto *params = (struct lcore_params *)lcore_args;

	uint32_t lcore_id = rte_lcore_id();

	// Note lcore_id==0 is reserved for main()
	if (lcore_id == 0) {
		rte_exit(EXIT_FAILURE, "Unexpectedly entered RSS handler from main thread\n");
	}

	uint16_t queue_id = lcore_id - 1;

	struct rte_mbuf *rx_packets[MAX_RX_BURST_SIZE];

	double tsc_to_seconds = 1.0 / (double)rte_get_timer_hz();

	DOCA_LOG_INFO("L-Core %d polling queue %d (all ports)", lcore_id, queue_id);

	while (!*params->force_quit) {
		for (uint16_t port_id = 0; port_id < rte_eth_dev_count_avail() && !*params->force_quit; port_id++) {
			uint64_t t_start = rte_rdtsc();

			uint16_t nb_rx_packets = rte_eth_rx_burst(port_id, queue_id, rx_packets, MAX_RX_BURST_SIZE);

			if (!nb_rx_packets)
				continue;

			for (int i = 0; i < nb_rx_packets && !*params->force_quit; i++) {
				handle_packet(params, port_id, queue_id, rx_packets[i]);
			}

			rte_pktmbuf_free_bulk(rx_packets, nb_rx_packets);

			if (params->config->show_rss_durations) {
				double sec = (double)(rte_rdtsc() - t_start) * tsc_to_seconds;
				printf("L-Core %d port %d: processed %d packets in %f seconds\n",
				       lcore_id,
				       port_id,
				       nb_rx_packets,
				       sec);
			}
		}
	}
	DOCA_LOG_INFO("L-Core %d exiting", lcore_id);

	return 0;
}

bool reinject_packet(struct rte_mbuf *packet, uint16_t port_id)
{
	uint32_t lcore_id = rte_lcore_id();
	if (lcore_id == 0) {
		DOCA_LOG_ERR("Cannot reinject packet from core 0");
		return false;
	}
	uint16_t queue_id = lcore_id - 1;

	uint16_t nsent = 0;
	for (uint16_t i = 0; i < max_tx_retries && nsent < 1; i++) {
		nsent = rte_eth_tx_burst(port_id, queue_id, &packet, 1);
	}
	return nsent == 1;
}
