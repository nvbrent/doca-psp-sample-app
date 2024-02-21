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

#ifndef _PSP_GW_BENCH_H_
#define _PSP_GW_BENCH_H_

#include <doca_error.h>

class PSP_GatewayFlows;
class PSP_GatewayImpl;

/**
 * @brief Performs all available DOCA Flow PSP benchmarks
 *
 * @flows [in]: The object which owns all the doca flow pipes and shared resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t psp_gw_run_benchmarks(PSP_GatewayFlows *flows);

#endif // _PSP_GW_BENCH_H_
