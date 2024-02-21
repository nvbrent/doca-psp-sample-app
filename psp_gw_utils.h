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

#ifndef _PSP_GW_UTILS_H_
#define _PSP_GW_UTILS_H_

#include <inttypes.h>
#include <string>

#include <rte_ether.h>
#include <rte_byteorder.h>

/**
 * @brief Converts an IPv4 address to a C++ string
 */
std::string ipv4_to_string(rte_be32_t ipv4_addr);

/**
 * @brief Converts an IPv6 address to a C++ string
 */
std::string ipv6_to_string(const uint8_t ipv6_addr[]);

/**
 * @brief Converts a MAC/ethernet address to a C++ string
 */
std::string mac_to_string(const rte_ether_addr &mac_addr);

#endif /* _PSP_GW_UTILS_H_ */
