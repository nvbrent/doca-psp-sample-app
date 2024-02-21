#
# Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

if not flag_enable_grpc_support
	set_variable('app_' + APP_NAME.underscorify() + '_disable_reason', 'Missing gRPC support')
	warning('Disabling psp_gateway; no grpc support')
	subdir_done()
endif

subdir('grpc')
app_dependencies += grpc_dependencies
app_dependencies += dependency_psp_gateway_grpc

app_srcs = files([
	'psp_gw_bench.cpp',
	'psp_gw_flows.cpp',
	'psp_gw_params.cpp',
	'psp_gw_svc_impl.cpp',
	'psp_gw_pkt_rss.cpp',
	'psp_gw_utils.cpp',
	common_dir_path + '/dpdk_utils.c',
	common_dir_path + '/pack.c',
	common_dir_path + '/utils.c',
	common_dir_path + '/flow_parser.c',
	samples_dir_path + '/common.c',
])

app_includes = files([
	'psp_gw_bench.h',
	'psp_gw_config.h',
	'psp_gw_flows.h',
	'psp_gw_params.h',
	'psp_gw_pkt_rss.h',
	'psp_gw_svc_impl.h',
	'psp_gw_utils.h',
])

install_srcs = app_srcs + app_includes

vanilla_app_srcs = files([
        APP_NAME + '.cpp',
])
install_srcs += vanilla_app_srcs

install_bins = files([
])

executable(DOCA_PREFIX + APP_NAME, app_srcs + vanilla_app_srcs,
	override_options: ['cpp_std=c++17'],
	c_args : apps_common_c_args,
    cpp_args: apps_common_cpp_args + grpc_cpp_args,
	dependencies : app_dependencies,
	include_directories: app_inc_dirs)
