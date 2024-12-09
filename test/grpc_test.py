#
# Copyright (c) 2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright notice, this list of
#       conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
#       to endorse or promote products derived from this software without specific prior written
#       permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ****************************************************************************
# File name: psp_gw_tool.py
# Description: utilities for interacting with the psp gateway sample DOCA application
# Python version: 3
# *****************************************************************************

from grpc_tools import protoc
import argparse
import os
import random
import sys
import grpc
import binascii
import secrets

def test_new_single_tunnel_request(args):
    from psp_gateway_pb2 import TunnelParameters, SingleTunnelRequest, MultiTunnelRequest
    from psp_gateway_pb2_grpc import PSP_GatewayStub
    channel = grpc.insecure_channel(f'{args.grpc_addr}:{args.grpc_port}')
    stub = PSP_GatewayStub(channel)
    tunnel_params = TunnelParameters()
    tunnel_params.mac_addr = args.tunnel_mac
    tunnel_params.ip_addr = args.tunnel_ip
    tunnel_params.psp_version = 1
    tunnel_params.spi = args.spi
    tunnel_params.encryption_key = secrets.token_bytes(32)
    tunnel_params.virt_cookie = args.virt_cookie
    new_tunnel_request = SingleTunnelRequest()
    new_tunnel_request.virt_src_ip = args.virt_src_ip
    new_tunnel_request.virt_dst_ip = args.virt_dst_ip
    new_tunnel_request.reverse_params.CopyFrom(tunnel_params)
    multi_tunnel_request = MultiTunnelRequest()
    multi_tunnel_request.request_id = args.request_id
    multi_tunnel_request.psp_versions_accepted.extend([1])
    for _ in range(args.nb_req):
        multi_tunnel_request.tunnels.extend([new_tunnel_request])
    print(f'Sending request:')
    print(f'\trequest_id: {multi_tunnel_request.request_id}')
    print(f'\tpsp_versions_accepted: {multi_tunnel_request.psp_versions_accepted}')
    print(f'\tvirt_src_ip: {new_tunnel_request.virt_src_ip}')
    print(f'\tvirt_dst_ip: {new_tunnel_request.virt_dst_ip}')
    print(f'\treverse_params:')
    print(f'\t\tmac_addr: {tunnel_params.mac_addr}')
    print(f'\t\tip_addr: {tunnel_params.ip_addr}')
    print(f'\t\tpsp_version: {tunnel_params.psp_version}')
    print(f'\t\tspi: {tunnel_params.spi}')
    print(f'\t\tencryption_key: {binascii.hexlify(tunnel_params.encryption_key).decode()}')
    print(f'\t\tvirt_cookie: {tunnel_params.virt_cookie}')
    response = stub.RequestMultipleTunnelParams(multi_tunnel_request)
    print(f'Received response:')
    print(f'\trequest_id: {response.request_id}')
    for tunnel in response.tunnels_params:
        print(f'\t\tmac_addr: {tunnel.mac_addr}')
        print(f'\t\tip_addr: {tunnel.ip_addr}')
        print(f'\t\tpsp_version: {tunnel.psp_version}')
        print(f'\t\tspi: {tunnel.spi}')
        print(f'\t\tencryption_key: {binascii.hexlify(tunnel.encryption_key).decode()}')
        print(f'\t\tvirt_cookie: {tunnel.virt_cookie}')

def test_key_rotation_request(args):
    from psp_gateway_pb2 import KeyRotationRequest
    from psp_gateway_pb2_grpc import PSP_GatewayStub
    channel = grpc.insecure_channel(f'{args.grpc_addr}:{args.grpc_port}')
    stub = PSP_GatewayStub(channel)
    key_rotation_request = KeyRotationRequest()
    key_rotation_request.request_id = args.request_id
    key_rotation_request.issue_new_keys = args.issue_new_keys
    print(f'Sending request:')
    print(f'\trequest_id: {key_rotation_request.request_id}')
    print(f'\tissue_new_keys: {key_rotation_request.issue_new_keys}')
    key_rotation_response = stub.RequestKeyRotation(key_rotation_request)
    print(f'Received response:')
    print(f'\trequest_id: {key_rotation_response.request_id}')

def generate_proto_files():
    tool_path = os.path.dirname(os.path.abspath(__file__))
    proto_path = f'{tool_path}/../grpc/'
    proto_file = f'{proto_path}/psp_gateway.proto'
    output_dir = f'/tmp/generated'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    res = protoc.main([
            'grpc_tools.protoc',
            f'--proto_path={proto_path}',
            f'--python_out={output_dir}',
            f'--pyi_out={output_dir}',
            f'--grpc_python_out={output_dir}',
            proto_file])
    if res:
        raise Exception(f'gRPC code generation failed with exit code {res}.')
    sys.path.append(output_dir)

def test_op_state(args):
    from psp_gateway_pb2 import OpState, OpStateMsg
    from psp_gateway_pb2_grpc import PSP_GatewayStub
    channel = grpc.insecure_channel(f'{args.grpc_addr}:{args.grpc_port}')
    stub = PSP_GatewayStub(channel)

    request = OpStateMsg()
    if args.op_state:
        request.op_state = OpState.Value(args.op_state)
        response = stub.SetOpState(request)
    else:
        response = stub.GetOpState(request)

    print(f'Received response:')
    print(f'\top_state: {OpState.Name(response.op_state)}')

# The tool supports multiple modes, each with its own set of arguments
available_modes = {
    'key_rotation': test_key_rotation_request,
    'new_tunnel': test_new_single_tunnel_request,
    'op_state': test_op_state,
}

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='PSP Gateway gRPC tool')
    subparsers = argparser.add_subparsers(dest='mode', required=True)
    for mode in available_modes.keys():
        mode_parser = subparsers.add_parser(mode)
        mode_parser.add_argument('--request-id', type=int, help='Request id for key rotation', default=random.randint(1, 1000))
        mode_parser.add_argument('--grpc_addr', type=str, help='gRPC server\'s IP address', default='localhost')
        mode_parser.add_argument('--grpc_port', type=int, help='gRPC server\'s port', default=3000)

        if mode == 'key_rotation':
            mode_parser.add_argument('--issue-new-keys', action='store_true', help='Issue new keys after key rotation')
        if mode == 'new_tunnel':
            mode_parser.add_argument('--tunnel-ip', type=str, help='Destination IPv6 address', default='fe80::1')
            mode_parser.add_argument('--tunnel-mac', type=str, help='Destination IPv6 address', default='aa:bb:cc:dd:ee:ff')
            mode_parser.add_argument('--virt_src_ip', type=str, help='Virtual source IPv4 address', default='192.168.1.1')
            mode_parser.add_argument('--virt_dst_ip', type=str, help='Virtual destination IPv4 address', default='192.168.1.2')
            mode_parser.add_argument('--spi', type=str, help='SPI to send in the request', default=random.randint(1, 1000))
            mode_parser.add_argument('--virt_cookie', type=str, help='Virtualization cookie to send in the request', default=random.randint(1, 1000))
            mode_parser.add_argument('--nb_req', type=int, help='number of requests to send', default=1)
        if mode == 'op_state':
            mode_parser.add_argument('--op_state', type=str, help='Make current instance active/standby')

    args = argparser.parse_args()
    generate_proto_files()
    available_modes[args.mode](args)
