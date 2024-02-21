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

#ifndef _PSP_GW_PKT_RSS_H
#define _PSP_GW_PKT_RSS_H

struct psp_gw_app_config;
class PSP_GatewayFlows;
class PSP_GatewayImpl;

/**
 * @brief The parameters needed by each L-Core's main loop.
 */
struct lcore_params {
	volatile bool *force_quit;	  /*!< Indicates the application has been requested to quit */
	struct psp_gw_app_config *config; /*!< Contains configuration information */
	PSP_GatewayFlows *psp_flows;	  /*!< The doca flow objects */
	PSP_GatewayImpl *psp_svc;	  /*!< The RPC service which manages tunnels */
};

/**
 * @brief The entry point for each L-Core's main processing loop.
 * Each L-Core polls a different Rx queue on the Host PF(s).
 * If the packet indicates the need for a new tunnel to be
 * established, it will be passed to the psp_svc object.
 * Note multiple such packets may be received during the
 * creation of the tunnel; in any case, they will be resubmitted
 * to the encryption pipeline once the new flow has been created.
 *
 * @lcore_args [in]: a pointer to an lcore_params struct
 * @return: 0 on success (the main loop exited normally), negative value otherwise
 */
int lcore_pkt_proc_func(void *lcore_args);

/**
 * @brief Used by the psp_svc to reinject a packet via the Host PF Tx queue after
 *        a new tunnel has been established.
 *
 * @packet [in]: the packet to submit into the egress pipeline
 * @port_id [in]: the port on which to send the packet, usually the host PF
 * @return: true if the packet was successfully sent, false if too many retries failed
 */
bool reinject_packet(struct rte_mbuf *packet, uint16_t port_id);

#endif // _PSP_GW_PKT_RSS_H
