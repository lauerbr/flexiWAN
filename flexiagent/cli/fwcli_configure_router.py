#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

import fwglobals
import fw_os_utils
import fwutils

from fwagent import fw_rpc
from fwcfg_request_handler import FwCfgMultiOpsWithRevert

def argparse(configure_subparsers):

    # Following are examples of the supported commands:
    #   >> fwagent configure router interfaces create --type lan --host_if_name vpp-vpn1 --addr 10.72.25.25/24 --no_vppsb --no_ospf --no_bgp --no_features --tap --dev_id pci:0000:00:08.0
    #   >> fwagent configure router interfaces delete --ignore_errors --type lan --vpp_if_name tap-vpn0 --addr 10.72.25.25/24 --no_ospf --no_bgp --no_features
    #   >> fwagent configure router span create --src_dev_id pci:0000:00:0a.00 --dest_vpp_if_name tap-ntop0
    #   >> fwagent configure router span delete --src_dev_id pci:0000:00:0a.00 --ignore_errors

    configure_router_parser = configure_subparsers.add_parser('router', help='Configure router')
    configure_router_subparsers = configure_router_parser.add_subparsers(dest='router')

    interfaces_parser = configure_router_subparsers.add_parser('interfaces', help='Configure interfaces')
    router_interfaces_subparsers = interfaces_parser.add_subparsers(dest='interfaces')

    create_interfaces_cli = router_interfaces_subparsers.add_parser('create', help='Create VPP interface')
    create_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface will be use to go to the internet", required=True)
    create_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='ADDRESS', help="The IPv4 to configure on the VPP interface, use NONE for no address", required=True)
    create_interfaces_cli.add_argument('--host_if_name', dest='params.host_if_name', metavar='LINUX_INTERFACE_NAME', help="The name of the interface that will be created in Linux side", required=True)
    create_interfaces_cli.add_argument('--dev_id', dest='params.dev_id', help="Device id", required=True)
    create_interfaces_cli.add_argument('--no_vppsb', dest='params.no_vppsb', help="If provided, VPPSB will not create Linux interface for it (but VPP will) - Do it if you know what you are doing", action='store_true')
    create_interfaces_cli.add_argument('--no_features', dest='params.no_features', help="If provided, features are not provisioned for the interface", action='store_true')
    create_interfaces_cli.add_argument('--no_ospf', dest='params.no_ospf', help="If provided, OSPF is not provisioned for the interface", action='store_true')
    create_interfaces_cli.add_argument('--no_bgp', dest='params.no_bgp', help="If provided, BGP is not provisioned for the interface", action='store_true')
    create_interfaces_cli.add_argument('--tap', dest='params.tap', help="If provided, interface is provisioned as tap, otherwise as tun (default)", action='store_true')

    remove_interfaces_cli = router_interfaces_subparsers.add_parser('delete', help='Remove VPP interface')
    remove_interfaces_cli.add_argument('--type', dest='params.type', choices=['wan', 'lan'], metavar='INTERFACE_TYPE', help="Indicates if interface is used to go to the internet", required=True)
    remove_interfaces_cli.add_argument('--addr', dest='params.addr', metavar='IP_ADDRESS', help="The IPv4 of VPP interface to remove, use NONE if no address is used", required=True)
    remove_interfaces_cli.add_argument('--vpp_if_name', dest='params.vpp_if_name', metavar='VPP_INTERFACE_NAME', help="VPP interface name", required=True)
    remove_interfaces_cli.add_argument('--ignore_errors', dest='params.ignore_errors', help="Ignore exceptions during removal", action='store_true')
    remove_interfaces_cli.add_argument('--no_features', dest='params.no_features', help="If provided, features are not removed from the interface", action='store_true')
    remove_interfaces_cli.add_argument('--no_ospf', dest='params.no_ospf', help="If provided, OSPF is not removed from the interface", action='store_true')
    remove_interfaces_cli.add_argument('--no_bgp', dest='params.no_bgp', help="If provided, BGP is not removed from the interface", action='store_true')

    span_parser = configure_router_subparsers.add_parser('span', help='Configure span')
    router_span_subparsers = span_parser.add_subparsers(dest='span')

    create_span_cli = router_span_subparsers.add_parser('create', help='Create VPP span')
    create_span_cli.add_argument('--src_dev_id', dest='params.src_dev_id', metavar='SOURCE_DEV_ID', help="Source device id", required=True)
    create_span_cli.add_argument('--dest_vpp_if_name', dest='params.dest_vpp_if_name', metavar='VPP_INTERFACE_NAME', help="Destination VPP interface name", required=True)

    remove_span_cli = router_span_subparsers.add_parser('delete', help='Remove VPP span')
    remove_span_cli.add_argument('--src_dev_id', dest='params.src_dev_id', metavar='SOURCE_DEV_ID', help="Source device id", required=True)
    remove_span_cli.add_argument('--ignore_errors', dest='params.ignore_errors', help="Ignore exceptions during removal", action='store_true')


@fw_rpc
def interfaces_create(type, addr, host_if_name, dev_id, no_vppsb, no_ospf=False, no_bgp=False,
                         no_features=False, tap=False):
    if not fw_os_utils.vpp_does_run():
        return

    if addr != 'NONE' and not fwutils.is_ipv4(addr):
        raise Exception(f'addr {addr} is not valid IPv4 address')
    if len(host_if_name) > 15:
        raise Exception(f'host_if_name {host_if_name} cannot have more then 15 characters')

    # Convert user friendly command line options into developer friendly variables :)
    #
    ospf     = not no_ospf
    bgp      = not no_bgp
    features = not no_features

    ret = {}
    with FwCfgMultiOpsWithRevert() as handler:
        try:
            # create tun
            tun_vpp_if_name = handler.exec(
                func=fwutils.create_tun_tap_in_vpp,
                params={ 'addr': addr, 'host_if_name': host_if_name, 'recreate_if_exists': True, 'no_vppsb': no_vppsb, 'is_tap': tap }
            )
            handler.add_revert_func(
                revert_func=fwutils.delete_tun_tap_from_vpp,
                revert_params={ 'vpp_if_name': tun_vpp_if_name, 'ignore_errors': False }
            )
            ret['tun_vpp_if_name'] = tun_vpp_if_name

            # apply features
            if features:
                handler.exec(
                    func=fwglobals.g.router_api.apply_features_on_interface,
                    params={ 'add': True, 'vpp_if_name': tun_vpp_if_name, 'dev_id': dev_id, 'if_type': type },
                    revert_func=fwglobals.g.router_api.apply_features_on_interface,
                    revert_params={ 'add': False, 'vpp_if_name': tun_vpp_if_name, 'dev_id': dev_id, 'if_type': type },
                )

            if ospf:
                _ret, err_str = handler.exec(
                    func=fwglobals.g.router_api.frr.run_ospf_add,
                    params={ 'address': addr, 'area': '0.0.0.0' },
                    revert_func=fwglobals.g.router_api.frr.run_ospf_remove,
                    revert_params={ 'address': addr, 'area': '0.0.0.0' },
                )
                if not _ret:
                    raise Exception(f'interfaces_create(): Failed to add {addr} network to ospf. err_str={err_str}')

            bgp_config = fwglobals.g.router_cfg.get_bgp() # check if BGP enabled
            if bgp and bgp_config:
                _ret, err_str = handler.exec(
                    func=fwglobals.g.router_api.frr.run_bgp_add_network,
                    params={ 'address': addr, 'local_asn': bgp_config.get('localAsn') },
                    revert_func=fwglobals.g.router_api.frr.run_bgp_remove_network,
                    revert_params={ 'address': addr, 'local_asn': bgp_config.get('localAsn') },
                )
                if not _ret:
                    raise Exception(f'interfaces_create(): Failed to add {addr} network to bgp. err_str={err_str}')

            return ret
        except Exception as e:
            handler.revert(e)
            raise e

@fw_rpc
def interfaces_delete(vpp_if_name, type, addr, no_ospf=False, no_bgp=False, no_features=False, ignore_errors=False):
    if not fw_os_utils.vpp_does_run():
        return

    if addr != 'NONE' and not fwutils.is_ipv4(addr):
        raise Exception(f'addr {addr} is not valid IPv4 address')

    # Convert user friendly command line options into developer friendly variables :)
    #
    ospf     = not no_ospf
    bgp      = not no_bgp
    features = not no_features

    with FwCfgMultiOpsWithRevert() as handler:
        try:
            if ospf:
                ret, err_str = handler.exec(
                    func=fwglobals.g.router_api.frr.run_ospf_remove,
                    params={ 'address': addr, 'area': '0.0.0.0' },
                )
                if not ret:
                    err_msg = f'api_interface_delete(): Failed to remove {addr} network from ospf. err_str={str(err_str)}'
                    if ignore_errors:
                        fwglobals.log.error(err_msg)
                    else:
                        raise Exception(err_msg)

            bgp_config = fwglobals.g.router_cfg.get_bgp()
            if bgp and bgp_config:
                ret, err_str = handler.exec(
                    func=fwglobals.g.router_api.frr.run_bgp_remove_network,
                    params={ 'address': addr, 'local_asn': bgp_config.get('localAsn') },
                )
                if not ret:
                    err_msg = f'api_interface_delete(): Failed to remove {addr} network from bgp. err_str={str(err_str)}'
                    if ignore_errors:
                        fwglobals.log.error(err_msg)
                    else:
                        raise Exception(err_msg)

            if features:
                handler.exec(
                    func=fwglobals.g.router_api.apply_features_on_interface,
                    params={ 'add': False, 'vpp_if_name': vpp_if_name, 'if_type': type },
                )
            handler.exec(
                func=fwutils.delete_tun_tap_from_vpp,
                params={ 'vpp_if_name': vpp_if_name, 'ignore_errors': ignore_errors},
            )

        except Exception as e:
            handler.revert(e)
            raise e

@fw_rpc
def span_create(src_dev_id, dest_vpp_if_name):
    if not fw_os_utils.vpp_does_run():
        return

    with FwCfgMultiOpsWithRevert() as handler:
        try:
            handler.exec(
                func=fwutils.create_span_in_vpp,
                params={ 'src_dev_id':src_dev_id, 'dest_vpp_if_name':dest_vpp_if_name, 'recreate_if_exists': True }
            )
            handler.add_revert_func(
                revert_func=fwutils.delete_span_from_vpp,
                revert_params={ 'src_dev_id':src_dev_id }
            )
        except Exception as e:
            handler.revert(e)
            raise e

@fw_rpc
def span_delete(src_dev_id, ignore_errors=False):
    if not fw_os_utils.vpp_does_run():
        return

    with FwCfgMultiOpsWithRevert() as handler:
        try:
            handler.exec(
                func=fwutils.delete_span_from_vpp,
                params={ 'src_dev_id':src_dev_id, 'ignore_errors': ignore_errors },
            )
        except Exception as e:
            handler.revert(e)
            raise e
