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


def get_nat_1to1_config(dev_id, internal_ip):
    """
    Generates command for 1:1 NAT configuration

    :param dev_id: device identifier of the WAN interface received from flexiManage
    :type dev_id: String
    :param internal_ip: Internal IP to which WAN IP need to be mapped
    :type internal_ip: String
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []
    cmd = {}
    ip_bytes, _ = fwutils.ip_str_to_bytes(internal_ip)

    add_params = {
        'is_add': 1,
        'substs': [
            {'add_param': 'external_sw_if_index',
            'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
        ],
        'local_ip_address': ip_bytes,
        'flags': 12 #[IS_OUT2IN_ONLY(0x4) | IS_ADDR_ONLY (0x8)]
    }

    revert_params = copy.deepcopy(add_params)
    revert_params['is_add'] = 0

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "call_vpp_api"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['descr'] = "Add NAT 1:1 rule"
    cmd['cmd']['params'] = {
                    'api':  "nat44_add_del_static_mapping",
                    'args': add_params
    }

    cmd['revert'] = {}
    cmd['revert']['func']   = "call_vpp_api"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['descr'] = "Delete NAT 1:1 rule"
    cmd['revert']['params'] = {
                    'api':  "nat44_add_del_static_mapping",
                    'args': revert_params
    }

    cmd_list.append(cmd)

    return cmd_list


def get_nat_port_forward_config(dev_id, protocols, ports, internal_ip,
                                internal_port_start):
    """
    Generates command for NAT Port forwarding configuration

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :param protocols: protocols for which the port forward is applied
    :type protocols: list
    :param ports: ports for which forwarding is applied
    :type ports: list
    :param internal_ip: Internal IP to which WAN IP need to be mapped
    :type internal_ip: String
    :param internal_port_start: Internal port start to be used
    :type internal_port_start: integer
    :raises Exception: If protocol value is unsupported
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []
    ip_bytes, _ = fwutils.ip_str_to_bytes(internal_ip)
    port_from, port_to = fwutils.ports_str_to_range(ports)
    port_iter = 0

    for port in range(port_from, (port_to + 1)):

        if not protocols:
            protocols = ['tcp', 'udp']
        for proto in protocols:

            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                    fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception(
                    'Invalid input : NAT Protocol input is wrong %s' % (proto))

            cmd = {}
            add_params = {
                'is_add': 1,
                'substs': [
                    {'add_param': 'external_sw_if_index',
                    'val_by_func': 'dev_id_to_vpp_sw_if_index', 'arg': dev_id}
                ],
                'local_ip_address': ip_bytes,
                'protocol': fwutils.proto_map[proto],
                'external_port': port,
                'local_port': internal_port_start + port_iter
            }
            revert_params = copy.deepcopy(add_params)
            revert_params['is_add'] = 0

            cmd['cmd'] = {}
            cmd['cmd']['func']   = "call_vpp_api"
            cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['cmd']['descr'] = "Add NAT Port Forward rule"
            cmd['cmd']['params'] = {
                            'api': "nat44_add_del_static_mapping",
                            'args': add_params
            }

            cmd['revert'] = {}
            cmd['revert']['func']   = "call_vpp_api"
            cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['revert']['descr'] = "Delete NAT Port Forward rule"
            cmd['revert']['params'] = {
                            'api': "nat44_add_del_static_mapping",
                            'args': revert_params
            }

            cmd_list.append(cmd)
        port_iter += 1

    return cmd_list


def get_nat_identity_config(dev_id, protocols, ports):
    """
    Generates command for NAT identity mapping configuration

    :param dev_id: device identifier of the WAN interface
    :type dev_id: String
    :param protocols: Protocols for which the edge access is to be enabled
    :type protocols: List
    :param ports: Ports for which the edge access is to be enabled
    :type ports: List
    :raises Exception: If protocol value is unsupported
    :return: Command params carrying the generated config
    :rtype: list
    """
    cmd_list = []
    port_from, port_to = fwutils.ports_str_to_range(ports)
    sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
    for port in range(port_from, (port_to + 1)):

        if not protocols:
            protocols = ['tcp', 'udp']
        for proto in protocols:

            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                    fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception(
                    'Invalid input : NAT Protocol input is wrong %s' % (proto))

            cmd = {}
            add_params = {
                'is_add': 1,
                'sw_if_index': sw_if_index,
                'protocol': fwutils.proto_map[proto],
                'port': port
            }
            revert_params = copy.deepcopy(add_params)
            revert_params['is_add'] = 0

            cmd['cmd'] = {}
            cmd['cmd']['func']   = "call_vpp_api"
            cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['cmd']['descr']  = "Add NAT identity mapping rule"
            cmd['cmd']['params'] = {
                'api' : 'nat44_add_del_identity_mapping',
                'args': add_params
            }

            cmd['revert'] = {}
            cmd['revert']['func']   = "call_vpp_api"
            cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
            cmd['revert']['descr']  = "Add NAT identity mapping rule"
            cmd['revert']['params'] = {
                'api' : 'nat44_add_del_identity_mapping',
                'args': revert_params
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


def exec_vpp_nat_api (config):
    """
    Execute the given VPP NAT API with the given parameters

    :param config: Configuration with the VPP API and its parameters
    :type config: dict
    :raises Exception: Raises exception if the VPP API call fails
    """
    rv = fwglobals.g.router_api.vpp_api.vpp.call (config['api'], **config['params'])
    retval = getattr(rv, 'retval') if rv else None
    if retval and retval != 0:
        raise Exception (f'Executing VPP NAT API failed {rv} - {str(config)}')
    fwglobals.log.debug(f'Executed VPP NAT API {rv} - {str(config)}')


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
