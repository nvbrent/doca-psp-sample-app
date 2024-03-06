#
# Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('psp_gateway', 'C', 'CPP',
	version: '0.0.1',
	default_options: ['buildtype=debug']
)

APP_NAME = meson.project_name()
DOCA_PREFIX = 'doca_'
apps_common_c_args = ''
apps_common_cpp_args = ''
grpc_cpp_args = ''

add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API', language: 'c')
add_project_arguments('-DDOCA_ALLOW_EXPERIMENTAL_API', language: 'cpp')

dependency_libdpdk = dependency('libdpdk', required : false)
if not dependency_libdpdk.found()
	error('Please set PKG_CONFIG_PATH to DPDK packages path, for further instructions please refer to the DOCA Reference Applications guide')
endif
app_dependencies = [dependency_libdpdk]
app_dependencies += dependency('json-c', required : true)
app_dependencies += dependency('threads', required : true)
app_dependencies += dependency('doca', required : true)

dependency_protobuf = dependency('protobuf', required : true)
dependency_grpc = dependency('grpc++', required : true)
grpc_dependencies = [dependency_protobuf, dependency_grpc]

subdir('grpc')
app_dependencies += grpc_dependencies
app_dependencies += dependency_psp_gateway_grpc

common_dir_path = '/opt/mellanox/doca/applications/common/src'
samples_dir_path = '/opt/mellanox/doca/samples'

app_inc_dirs = [include_directories(common_dir_path)]

app_srcs = files([
	APP_NAME + '.cpp',
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

executable(DOCA_PREFIX + APP_NAME, app_srcs,
	override_options: ['cpp_std=c++17'],
	c_args : apps_common_c_args,
    cpp_args: apps_common_cpp_args + grpc_cpp_args,
	dependencies : app_dependencies,
	include_directories: app_inc_dirs)
