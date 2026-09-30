"""
Helper functions to convert NAT configurations into VPP NAT commands
"""

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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

import copy
import fwutils
import fwglobals
import ipaddress

def get_nat_forwarding_config(enable):
    """
    Generates commands to enable/disable nat44 forwarding configuration

    :param enable: Carries value indicating it it need to be enabled
    :type enable: Boolean
    :return: Command params carrying the generated config
    :rtype: dict
    """

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']  = "call_vpp_api"
    cmd['cmd']['descr'] = "Set NAT forwarding"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
                    'api': "nat44_forwarding_enable_disable",
                    'args': {'enable': enable}
    }
    return cmd

def get_nat_wan_setup_config(dev_id):
    """
    Generates command to enable NAT and required default identity mappings
    on WAN interfaces

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr'] = "Enable NAT output feature on interface %s " % (
        dev_id)
    cmd['cmd']['params'] = {
                    'api': "nat44_interface_add_del_output_feature",
                    'args': {
                        'is_add': 1,
                        'substs': [
                            {'add_param': 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ]
                    }
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr'] = "Disable NAT output feature on interface %s " % (
        dev_id)
    cmd['revert']['params'] = {
                    'api': "nat44_interface_add_del_output_feature",
                    'args': {
                        'is_add': 0,
                        'substs': [
                            {'add_param': 'sw_if_index',
                            'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ]
                    }
    }
    cmd_list.append(cmd)

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "vpp_wan_tap_inject_configure"
    cmd['cmd']['module'] = "fwutils"
    cmd['cmd']['descr'] = "enable forward of tap-inject to ip4-output features %s" % dev_id
    cmd['cmd']['params'] = {
                    'dev_id': dev_id,
                    'remove': False,
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "vpp_wan_tap_inject_configure"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['descr'] = "disable forward of tap-inject to ip4-output features %s" % dev_id
    cmd['revert']['params'] = {
                        'dev_id': dev_id,
                        'remove': True,
    }
    cmd_list.append(cmd)

    return cmd_list


def get_vpp_identity_nat_params (is_add, sw_if_index, external_ip_address, protocol, port):
    """
    Get the VPP API's configuration parameters for setting identity NAT

    :param is_add: Flag to indicate add and remove
    :type is_add: bool
    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: Integer
    :param protocol: Variable indicating 'tcp' or 'udp'
    :type protocol: String
    :param external_ip_address: IP address to be used in the rule
    :type external_ip_address: Byte array of the IP address
    :param port: Port address to be configured in the identity NAT
    :type port: Integer
    :return: Configuration parameter for setup and revert
    :rtype: dict, dict
    """
    config = {
        'api'    : 'nat44_add_del_identity_mapping',
        'params' : {
            'is_add'      : is_add,
            'sw_if_index' : sw_if_index,
            'ip_address'  : external_ip_address,
            'protocol'    : fwutils.proto_map[protocol],
            'port'        : port,
        }
    }
    revert_config = copy.deepcopy(config)
    revert_config['params']['is_add'] = not is_add
    return config, revert_config


def get_vpp_port_mapping_nat_params (is_add, external_sw_if_index, external_ip_address, protocol,
                                     external_port, local_ip_address, local_port):
    """
    Get the VPP API's configuration parameters for setting Port Mapping NAT

    :param is_add: Flag to indicate add and remove
    :type is_add: bool
    :param external_sw_if_index:  VPP identifier of the interface
    :type external_sw_if_index: Integer
    :param external_ip_address: IP address to be used in the rule
    :type external_ip_address: Byte array of the IP address
    :param protocol: Variable indicating 'tcp' or 'udp'
    :type protocol: String
    :param external_port: External port address
    :type external_port: Integer
    :param local_ip_address: Local IP address to which external address is to be mapped
    :type local_ip_address: Bytes array
    :param local_port: Local Port address to which external port is to be mapped
    :type local_port: Integer
    :return: Configuration parameter for setup and revert
    :rtype: dict, dict
    """
    config = {
        'api'    : 'nat44_add_del_static_mapping',
        'params' : {
            'is_add'               : is_add,
            'external_sw_if_index' : external_sw_if_index,
            'external_ip_address'  : external_ip_address,
            'protocol'             : fwutils.proto_map[protocol],
            'external_port'        : external_port,
            'local_ip_address'     : local_ip_address,
            'local_port'           : local_port,
            'flags'                : 4 #[IS_OUT2IN_ONLY(0x4)]
        }
    }
    revert_config = copy.deepcopy(config)
    revert_config['params']['is_add'] = not is_add
    return config, revert_config

def get_vpp_1to1_nat_params (is_add, sw_if_index, external_ip_address, local_ip_address):
    """
    Get the VPP API's configuration parameters for setting 1to1 NAT

    :param is_add: Flag to indicate add and remove
    :type is_add: bool
    :param sw_if_index:  VPP identifier of the interface
    :type sw_if_index: Integer
    :param external_ip_address: IP address to be used in the rule
    :type external_ip_address: Byte array of the IP address
    :param local_ip_address: Local IP address to which external address is to be mapped
    :type local_ip_address: Bytes array
    :return: Configuration parameter for setup and revert
    :rtype: dict, dict
    """
    config = {
        'api'    : 'nat44_add_del_static_mapping',
        'params' : {
            'is_add'               : is_add,
            'external_sw_if_index' : sw_if_index,
            'external_ip_address'  : external_ip_address,
            'local_ip_address'     : local_ip_address,
            'flags'                : 12 #[IS_OUT2IN_ONLY(0x4) | IS_ADDR_ONLY (0x8)]
        }
    }
    revert_config = copy.deepcopy(config)
    revert_config['params']['is_add'] = not is_add
    return config, revert_config


def exec_vpp_api_config (config, api_descr):
    """
    Execute the VPP API with parameters, described by the configuration built
    by the get_vpp_X_params() helpers.

    :param config: Configuration with the VPP API and its parameters
    :type config: dict
    :param api_descr: Description of the API for logs, e.g. 'NAT'
    :type api_descr: str
    :raises Exception: Raises exception if the VPP API call fails
    """
    rv = fwglobals.g.router_api.vpp_api.vpp.call (config['api'], **config['params'])
    retval = getattr(rv, 'retval') if rv else None
    if retval and retval != 0:
        raise Exception (f'Executing VPP {api_descr} API failed {rv} - {str(config)}')
    fwglobals.log.debug(f'Executed VPP {api_descr} API {rv} - {str(config)}')


def exec_vpp_nat_api (config):
    """
    Execute the given VPP NAT API with the given parameters.
    Note the function is referenced by name in the stored command lists.

    :param config: Configuration with the VPP API and its parameters
    :type config: dict
    :raises Exception: Raises exception if the VPP API call fails
    """
    exec_vpp_api_config(config, 'NAT')


def get_add_nat_address_command(dev_id, nat_ip_list):
    """
    Generate VPP command to add the given IP addresses to the interface's NAT address pool

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :param nat_ip_list: List of IP addresses or subnets to be added as NAT addresses
    :type nat_ip_list: list
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []
    for ip_str in nat_ip_list:
        net_address = ipaddress.ip_network(ip_str)
        ip_str_start = ip_str.split('/')[0] if '/' in ip_str else ip_str
        ip_end = int(ipaddress.ip_address(ip_str_start)) + net_address.num_addresses - 1
        ip_str_end = str(ipaddress.ip_address(ip_end))
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "call_vpp_api"
        cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['cmd']['descr']  = f'Add NAT IP address {ip_str} to interface {dev_id}'
        cmd['cmd']['params'] = {
            'api': "nat44_add_del_address_range",
            'args': {
                'first_ip_address' : ip_str_start,
                'last_ip_address' : ip_str_end,
                'is_add': True,
                'vrf_id': 0xFFFFFFFF, #not tied to any vrf id
                'sw_if_index_count': 1,
                'substs': [
                    {
                        'add_param'  : 'sw_if_index_array',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index_array',
                        'arg'        : { 'dev_id_array': [dev_id] }
                    },
                ],
            }
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "call_vpp_api"
        cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
        cmd['revert']['descr']  = f'Delete NAT IP address {ip_str} from interface {dev_id}'
        cmd['revert']['params'] = {
            'api': "nat44_add_del_address_range",
            'args': {
                'first_ip_address' : ip_str_start,
                'last_ip_address' : ip_str_end,
                'is_add': False,
                'vrf_id': 0xFFFFFFFF,
                'sw_if_index_count': 1,
                'substs': [
                    {
                        'add_param'  : 'sw_if_index_array',
                        'val_by_func': 'dev_id_to_vpp_sw_if_index_array',
                        'arg'        : { 'dev_id_array': [dev_id] }
                    },
                ],
            }
        }
        cmd_list.append(cmd)
    return cmd_list


def get_wan_interface_addr_setup_config(dev_id):
    """
    Generates command to add WAN interface NAT address

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :return: Command params carrying the generated config
    :rtype: dict
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr'] = "enable NAT for interface address %s" % dev_id
    cmd['cmd']['params'] = {
                    'api': "nat44_add_del_interface_addr",
                    'args': {
                        'is_add': 1,
                        'is_session_recovery': 1, #session recovery is enabled (adds resiliency on address flap)
                        'substs': [
                            {'add_param': 'sw_if_index',
                             'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ],
                    }
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr'] = "disable NAT for interface %s" % dev_id
    cmd['revert']['params'] = {
                    'api': "nat44_add_del_interface_addr",
                    'args': {
                        'is_add': 0,
                        'substs': [
                            {'add_param': 'sw_if_index',
                             'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                        ],
                    }
    }
    return cmd
