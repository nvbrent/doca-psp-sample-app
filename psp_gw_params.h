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

#ifndef _PSP_GW_PARAMS_H_
#define _PSP_GW_PARAMS_H_

#include <string>
#include <vector>
#include <doca_error.h>

/**
 * @brief Parses command-line arguments to the application.
 * During processing of arguments, both DPDK and the application
 * may remove arguments from argv, and argc will reflect the
 * new size.
 *
 * @argc [in/out]: The number of args passed to main()
 * @argv [in/out]: The args passed to main
 * @app_config [out]: The configuration of the application
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t psp_gw_argp_exec(int &argc, char *argv[], psp_gw_app_config *app_config);

#endif /* _PSP_GW_PARAMS_H_ */
