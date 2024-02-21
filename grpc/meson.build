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

protoc = find_program('protoc')
grpc_cpp_plugin = find_program('grpc_cpp_plugin')

protobuf_gen_cc = generator(protoc, \
    output    : ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
    arguments : [
        '--cpp_out=@BUILD_DIR@',
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '@INPUT@'])

grpc_gen_cc = generator(protoc, \
    output    : ['@BASENAME@.grpc.pb.cc', '@BASENAME@.grpc.pb.h'],
    arguments : [
        '--grpc_out=@BUILD_DIR@',
        '--proto_path=@CURRENT_SOURCE_DIR@',
        '--plugin=protoc-gen-grpc=' + grpc_cpp_plugin.full_path(),
        '@INPUT@'])

psp_gateway_generated_proto_src = protobuf_gen_cc.process('psp_gateway.proto')
psp_gateway_generated_grpc_src = grpc_gen_cc.process('psp_gateway.proto')

lib_psp_gateway_grpc = static_library('psp_gateway_grpc',
    psp_gateway_generated_proto_src,
    psp_gateway_generated_grpc_src,
    cpp_args: grpc_cpp_args,
	dependencies : grpc_dependencies)

dependency_psp_gateway_grpc = declare_dependency(
    link_with: lib_psp_gateway_grpc,
    include_directories: lib_psp_gateway_grpc.private_dir_include())
