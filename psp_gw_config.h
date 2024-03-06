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

#ifndef _PSP_GW_FLOWS_H_
#define _PSP_GW_FLOWS_H_

#include <rte_ether.h>
#include <string>
#include <vector>

#include <doca_types.h>
#include <dpdk_utils.h>

// 0: PSP Header Version 0, AES-GCM-128
// 1: PSP Header Version 0, AES-GCM-256
// 2: PSP Header Version 0, AES-GMAC-128
// 3: PSP Header Version 0, AES-GMAC-256
static constexpr uint32_t SUPPORTED_PSP_VER = 1;

static constexpr uint32_t IPV6_ADDR_LEN = 16;
typedef uint8_t ipv6_addr_t[IPV6_ADDR_LEN];

/**
 * @brief Describes a host which is capable of exchanging
 *        traffic flows over a PSP tunel.
 *
 * Currently, only one PF per host is supported, but this
 * could be extended to a list of PFs.
 */
struct psp_gw_host {
	doca_be32_t vip;    /*!< virtual IP address, one per host PF */
	doca_be32_t svc_ip; /*!< control plane gRPC service address */
};

/**
 * @brief describes a network of hosts which participate
 *        in a network of PSP tunnel connections.
 */
struct psp_gw_net_config {
	std::vector<psp_gw_host> hosts; //!< The list of participating hosts and their interfaces

	bool vc_enabled; //!< Whether Virtualization Cookies shall be included in the PSP headers
};

/**
 * @brief describes the configuration of the PSP networking service on
 *        the local host.
 */
struct psp_gw_app_config {
	struct application_dpdk_config dpdk_config; //!< Configuration details of DPDK ports and queues

	std::string pf_pcie_addr;    //!< PCI domain:bus:device:function string of the host PF
	std::string pf_repr_indices; //!< Representor list string, such  as vf0 or pf[0-1]

	std::string local_svc_addr; //!< The IPv4 addr (and optional port number) of the locally running gRPC service.

	uint32_t max_tunnels; //!< The maximum number of outgoing tunnel connections supported on this host

	struct psp_gw_net_config net_config; //!< List of remote hosts supporting PSP connections

	/**
	 * The rate of sampling user packets is controlled by a uint16_t mask.
	 * This parameter determines how many bits of the mask should be set,
	 * with more bits indicating fewer packets to sample.
	 * (i.e. packet.meta.rand & mask == 1, where mask = (1<<N)-1)
	 *  0 -> sample no packets
	 *  1 -> sample 1 in 2
	 *  2 -> sample 1 in 4
	 * ...
	 * 16 -> sample 1 in 2^16 ~ 64K
	 * SAMPLE_RATE_DISABLED -> sampling disabled
	 */
	uint16_t log2_sample_rate;

	uint32_t sample_meta_indicator;

	bool create_tunnels_at_startup; //!< Create PSP tunnels at startup vs. on demand
	bool show_rss_rx_packets;	//!< Display to the console any packets received via RSS
	bool show_rss_durations;	//!< Display performance information for RSS processing
	bool debug_keys;		//!< Print the contents of PSP encryption keys to the console
	bool run_benchmarks_and_exit;	//!< Run PSP performance benchmarks; do not run the gRPC service.
};

#endif // _PSP_GW_CONFIG_H_
