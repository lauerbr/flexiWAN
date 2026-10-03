"""
Translates firewall request to a set of commands
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
import socket
import ctypes

import fwglobals
import fwutils
import fw_acl_command_helpers
import fw_nat_command_helpers
from fwfirewall import FwFirewall
from fwcfg_request_handler import FwCfgMultiOpsWithRevert

DEFAULT_ALLOW_ID  = 'fw_default_allow_id'
APP_FIREWALL_DEV_ID_PREFIX = 'app_'

def get_ingress_acl_key(rule):
    return rule['id'] + ':ingress'

def get_egress_acl_key(rule):
    return rule['id'] + ':egress'

def get_firewall_map_acl_keys_command():
    """
    Generate command to map ACL keys to ACL index
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "map_acl_keys_to_acl_id"
    cmd['cmd']['module'] = "fwfirewall"
    cmd['cmd']['descr']  = "Map Firewall ACL keys to actual ACL Index"
    cmd['cmd']['params'] = {
        'cmd_cache': fwglobals.g.router_api.cmd_cache
    }
    return cmd


def setup_wan_nat_rules (is_add, inbound_rules=None, dev_id=None, handler=None):
    """
    The function that sets up all the WAN NAT configurations as per the firewall policy

    :param is_add: Flag to indicate add and remove
    :type is_add: bool
    :param inbound_rules: Inbound params section of the firewall message, defaults to None
    :type inbound_rules: dict, optional
    :param dev_id: Unique device identifier of the interface, defaults to None
    :type dev_id: String, optional
    """

    def exec_nat_identity_rules (is_add, dev_id, destination, handler):
        """
        Setup VPP NAT Identity rule based on the given configuration parameters

        :param is_add: Flag to indicate add and remove
        :type is_add: bool
        :param dev_id: Unique device identifier of the interface
        :type dev_id: String
        :param destination: Configuration in the 'destination' section of the identity nat rule
        :type destination: dict
        :param handler: Instance handling the multi-config execution and revert
        :type handler: FwCfgMultiOpsWithRevert instance
        :raises Exception: Raises exception on invalid input
        """
        ip4_address = destination.get('ip4Address')
        port_from, port_to = fwutils.ports_str_to_range(destination['ports'])
        protocols = destination['protocols']
        if not protocols:
            protocols = ['tcp', 'udp']
        for proto in protocols:
            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                    fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception (f'Set identity NAT - Wrong protocol input {proto}')

        for port in range(port_from, (port_to + 1)):
            for proto in protocols:
                external_ip_address = socket.inet_pton(socket.AF_INET, ip4_address) \
                    if ip4_address else None
                sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id) \
                    if not ip4_address else 0xFFFFFFFF
                config, revert_config = fw_nat_command_helpers.get_vpp_identity_nat_params \
                    (is_add, sw_if_index, external_ip_address, proto, port)
                handler.exec(
                    func = fw_nat_command_helpers.exec_vpp_nat_api,
                    params = { 'config': config },
                    revert_func = fw_nat_command_helpers.exec_vpp_nat_api if is_add else None,
                    revert_params= { 'config' : revert_config }
                )


    def exec_port_mapping_rules (is_add, dev_id, destination, action, handler):
        """
        Setup VPP NAT port mapping rule based on the given configuration parameters

        :param is_add: Flag to indicate add and remove
        :type is_add: bool
        :param dev_id: Unique device identifier of the interface
        :type dev_id: String
        :param destination: Configuration in the 'destination' section of the port mapping rule
        :type destination: dict
        :param action: Configuration in the 'action' section of the port mapping rule
        :type action: dict
        :param handler: Instance handling the multi-config execution and revert
        :type handler: FwCfgMultiOpsWithRevert instance
        """
        ip4_address = destination.get('ip4Address')
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id) if not ip4_address else 0xFFFFFFFF
        external_ip_address = socket.inet_pton(socket.AF_INET, ip4_address) if ip4_address else None
        local_ip_address = socket.inet_pton(socket.AF_INET, action['internalIP'])
        local_port = action['internalPortStart']
        port_from, port_to = fwutils.ports_str_to_range(destination['ports'])
        port_iter = 0
        protocols = destination.get('protocols', None)
        if not protocols:
            protocols = ['tcp', 'udp']
        for proto in protocols:
            if (fwutils.proto_map[proto] != fwutils.proto_map['tcp'] and
                    fwutils.proto_map[proto] != fwutils.proto_map['udp']):
                raise Exception ('Set Port Mapping NAT - Wrong protocol input' % (proto))

        for port in range(port_from, (port_to + 1)):
            for proto in protocols:
                config, revert_config = fw_nat_command_helpers.get_vpp_port_mapping_nat_params \
                    (is_add, sw_if_index, external_ip_address, proto, port,
                     local_ip_address, local_port + port_iter)
                handler.exec(
                    func = fw_nat_command_helpers.exec_vpp_nat_api,
                    params = { 'config': config },
                    revert_func = fw_nat_command_helpers.exec_vpp_nat_api if is_add else None,
                    revert_params={'config' : revert_config }
                )
            port_iter += 1


    def exec_1to1_nat_rules (is_add, dev_id, destination, action, handler):
        """
        Setup VPP 1to1 NAT rule based on the given configuration parameters

        :param is_add: Flag to indicate add and remove
        :type is_add: bool
        :param dev_id: Unique device identifier of the interface
        :type dev_id: String
        :param destination: Configuration in the 'destination' section of the 1to1 NAT rule
        :type destination: dict
        :param action: Configuration in the 'action' section of the 1to1 NAT rule
        :type action: dict
        :param handler: Instance handling the multi-config execution and revert
        :type handler: FwCfgMultiOpsWithRevert instance
        """
        ip4_address = destination.get('ip4Address')
        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id) if not ip4_address else 0xFFFFFFFF
        external_ip_address = socket.inet_pton(socket.AF_INET, ip4_address) if ip4_address else None
        local_ip_address = socket.inet_pton(socket.AF_INET, action['internalIP'])
        config, revert_config = fw_nat_command_helpers.get_vpp_1to1_nat_params \
            (is_add, sw_if_index, external_ip_address, local_ip_address)
        handler.exec(
            func = fw_nat_command_helpers.exec_vpp_nat_api,
            params = { 'config': config },
            revert_func = fw_nat_command_helpers.exec_vpp_nat_api if is_add else None,
            revert_params={'config' : revert_config }
        )


    def process_inbound_nat_rules(is_add, rules, handler, match_dev_id=None):
        """
        Iterate over all the inbound NAT rules and set them up in VPP

        :param is_add: Flag to indicate add and remove
        :type is_add: bool
        :param rules: Rules contained in the inbound section of the firewall message
        :type rules: dict
        :param handler: Instance handling the multi-config execution and revert
        :type handler: FwCfgMultiOpsWithRevert instance
        :param match_dev_id: Unique device identifier of the interface, defaults to None
        :type match_dev_id: String, optional
        :raises Exception: Raises exception on invalid input
        """
        for rule_name, rules in inbound_rules.items():

            for rule in rules['rules']:
                classification = rule.get('classification')
                destination = classification.get('destination')
                action = rule.get('action')
                interface = destination.get('interface')
                dev_ids = [interface] if interface else []
                if dev_ids:
                    for dev_id in dev_ids:
                        if match_dev_id and match_dev_id != dev_id:
                            continue
                        if rule_name == "edgeAccess":
                            exec_nat_identity_rules (is_add, dev_id, destination, handler)
                        elif rule_name == "portForward":
                            exec_port_mapping_rules (is_add, dev_id, destination, action, handler)
                        elif rule_name == "nat1to1":
                            exec_1to1_nat_rules (is_add, dev_id, destination, action, handler)
                else:
                    if rule_name != "edgeAccess":
                        raise Exception ('Invalid - Global rule allowed only for EdgeAccess rule')
                    if match_dev_id:
                        exec_nat_identity_rules (is_add, match_dev_id, destination, handler)
                    else:
                        interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
                        for interface in interfaces:
                            dev_id = interface['dev_id']
                            exec_nat_identity_rules (is_add, dev_id, destination, handler)

    if not inbound_rules:
        firewall_params = fwglobals.g.router_cfg.get_firewall_policy()
        inbound_rules = firewall_params.get('inbound')
        if not inbound_rules:
            return
    if not handler:
        with FwCfgMultiOpsWithRevert() as handler:
            try:
                process_inbound_nat_rules (is_add, inbound_rules, handler, dev_id)
            except Exception as e:
                fwglobals.g.log.error(f"setup_wan_nat_rules({is_add}): failed. {str(e)}")
                handler.revert(e)
                raise
    else:
        process_inbound_nat_rules (is_add, inbound_rules, handler, dev_id)

def get_setup_wan_nat_command(inbound_rules):
    """
    Generates the command to set up WAN NAT configurations

    :param inbound_rules: Configuration carries in the inbound section of the firewall message
    :type inbound_rules: dict
    :return: Command structure to execute the WAN NAT configuration
    :rtype: dict
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "setup_wan_nat_rules"
    cmd['cmd']['module'] = "fwtranslate_add_firewall_policy"
    cmd['cmd']['descr']  = "Setup WAN NAT rules"
    cmd['cmd']['params'] = { 'is_add' : True, 'inbound_rules': inbound_rules, 'dev_id': None }

    cmd['revert'] = {}
    cmd['revert']['func']   = "setup_wan_nat_rules"
    cmd['revert']['module'] = "fwtranslate_add_firewall_policy"
    cmd['revert']['descr']  = "Revert WAN NAT rules"
    cmd['revert']['params'] = { 'is_add' : False, 'inbound_rules': inbound_rules, 'dev_id': None }
    return cmd

def setup_lan_acl_attachments_cmd(attachments, global_ingress_keys, global_egress_keys):
    """
    Generate the command to setup LAN ACL attachments

    :return: Command structure to execute the Interface ACL attachment
    :rtype: dict
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "setup_lan_acl_attachments"
    cmd['cmd']['module'] = "fwtranslate_add_firewall_policy"
    cmd['cmd']['descr']  = "Setup LAN ACL rules"
    cmd['cmd']['params'] = {
        'attachments'         : attachments,
        'global_ingress_keys' : global_ingress_keys,
        'global_egress_keys'  : global_egress_keys
    }

    cmd['revert'] = {}
    cmd['revert']['func']   = "clear_acl_attachments"
    cmd['revert']['module'] = "fwtranslate_add_firewall_policy"
    cmd['revert']['descr']  = "Revert LAN ACL rules"
    return cmd

def setup_wan_acl_attachments_cmd(attachments, global_ingress_keys):
    """
    Generate the command to setup WAN ACL attachments

    :return: Command structure to execute the Interface ACL attachment
    :rtype: dict
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "setup_wan_acl_attachments"
    cmd['cmd']['module'] = "fwtranslate_add_firewall_policy"
    cmd['cmd']['descr']  = "Setup WAN ACL rules"
    cmd['cmd']['params'] = {
        'attachments'         : attachments,
        'global_ingress_keys' : global_ingress_keys,
    }

    cmd['revert'] = {}
    cmd['revert']['func']   = "clear_acl_attachments"
    cmd['revert']['module'] = "fwtranslate_add_firewall_policy"
    cmd['revert']['descr']  = "Revert WAN ACL rules"
    return cmd

def exec_vpp_acl_attach_api(config):
    """
    Execute VPP API to attach ACLs to an interface.
    Note the function is referenced by name in the stored command lists.

    :param config: API configuration parameters
    :type config: dict
    :raises Exception: Raises exception if VPP API command execution fails
    """
    fw_nat_command_helpers.exec_vpp_api_config(config, 'ACL Attach')

def vpp_attach_acls (sw_if_index, ingress_keys, egress_keys, handler, firewall):
    """
    Builds VPP's ACL attachment command and executes the attachment.
    It uses the firewall object context to map the ACL keys to VPP-ACL ID.

    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: Integer
    :param ingress_keys: Array of ACL keys to be attached at the interface ingress
    :type ingress_keys: Array
    :param egress_keys: Array of ACL keys to be attached at the interface egress
    :type egress_keys: Array
    :param handler: Instance handling the multi-config execution and revert
    :type handler: FwCfgMultiOpsWithRevert instance
    :param firewall: Firewall class instance that maintains contexts in DB
    :type firewall: FwFirewall instance
    """
    ingress_acls = []
    egress_acls = []
    if ingress_keys:
        for acl_key in ingress_keys:
            ingress_acls.append(firewall.get_acl_id (acl_key))
    if egress_keys:
        for acl_key in egress_keys:
            egress_acls.append(firewall.get_acl_id (acl_key))

    config, revert_config = fw_acl_command_helpers.get_vpp_acl_attach_params \
        (sw_if_index, ingress_acls, egress_acls)
    handler.exec(
        func = exec_vpp_acl_attach_api,
        params = { 'config': config },
        revert_func = exec_vpp_acl_attach_api,
        revert_params= { 'config' : revert_config }
    )

def get_app_firewall_dev_id(app_identifier):
    return f'{APP_FIREWALL_DEV_ID_PREFIX}{app_identifier}'

def vpp_if_name_to_app_firewall_dev_id(vpp_if_name):
    vpp_interfaces = fwglobals.g.applications_api.get_interfaces(vpp_interfaces=True, linux_interfaces=False)
    for app_identifier, app_vpp_if_names in vpp_interfaces.items():
        for app_vpp_if_name in app_vpp_if_names:
            if vpp_if_name == app_vpp_if_name:
                return get_app_firewall_dev_id(app_identifier)
    return None

def get_app_sw_if_index_list (app_id=None, type='lan'):
    """
    Return the list of sw_if_index associated with the given application identifier and
    interface type

    :param type: Application name to be matched
    :type type: String, optional
    :param type: Value indicating the type of interface
    :type type: String, optional
    :return: List of sw_if_index and application identifier matching the given interface type
    :rtype: List, List
    """
    sw_if_index_list = []
    app_id_list = []
    app_interfaces = fwglobals.g.applications_api.get_interfaces\
        (type=type, vpp_interfaces=True, linux_interfaces=False)
    for app_identifier, vpp_if_names in app_interfaces.items():
        if app_id and (app_id != get_app_firewall_dev_id(app_identifier)):
            continue
        for vpp_if_name in vpp_if_names:
            sw_if_index = fwutils.vpp_if_name_to_sw_if_index (vpp_if_name)
            if sw_if_index is not None:
                sw_if_index_list.append(sw_if_index)
                app_id_list.append(get_app_firewall_dev_id(app_identifier))
            else:
                fwglobals.g.log.error('Failed to get sw_if_index from vpp_if_name : %s(app_id: %s)'\
                                      % (vpp_if_names, app_identifier))
    return sw_if_index_list, app_id_list

def setup_lan_acl_attachments(attachments, global_ingress_keys, global_egress_keys):
    """
    Setup ACL attachment to the LAN interfaces

    :param attachments: Interfaces and their ACL attachment values
    :type attachments: dict
    :param global_ingress_keys: Array of Global (All LAN interface) ACL keys to be\
        attached at the interface ingress
    :type global_ingress_keys: Array
    :param global_egress_keys: Array of Global (All LAN interface) ACL keys to be\
        attached at the interface egress
    :type global_egress_keys: Array
    """
    with FwCfgMultiOpsWithRevert() as handler, FwFirewall() as firewall:
        try:
            # Process interface specific rules
            for dev_id, value in attachments.items():
                # Add last default ACL as allow ALL
                value['ingress'].append(DEFAULT_ALLOW_ID)
                value['egress'].append(DEFAULT_ALLOW_ID)

                # handle application interfaces
                if dev_id.startswith(APP_FIREWALL_DEV_ID_PREFIX):
                    sw_if_index_list, _ = get_app_sw_if_index_list(dev_id)
                    for _, sw_if_index in enumerate(sw_if_index_list):
                        vpp_attach_acls (sw_if_index, value['ingress'], value['egress'], handler,
                                         firewall)
                        firewall.add_to_acl_interfaces(sw_if_index)
                else:
                    sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
                    vpp_attach_acls (sw_if_index, value['ingress'], value['egress'], handler,
                                     firewall)
                    firewall.add_to_acl_interfaces(sw_if_index)
            if not global_ingress_keys and not global_egress_keys:
                return
            if global_ingress_keys:
                global_ingress_keys.append(DEFAULT_ALLOW_ID)
            if global_egress_keys:
                global_egress_keys.append(DEFAULT_ALLOW_ID)

            # Prepare list of all LAN interfaces
            lan_dev_id_list = []
            lan_interfaces = fwglobals.g.router_cfg.get_interfaces(type='lan')
            for dev in lan_interfaces:
                dev_id = dev['dev_id']
                lan_dev_id_list.append (dev_id)
            _, app_dev_id_list = get_app_sw_if_index_list ()
            lan_dev_id_list.extend (app_dev_id_list)

            # Process global rules
            for dev_id in lan_dev_id_list:
                if not dev_id in attachments.keys():
                    if dev_id.startswith(APP_FIREWALL_DEV_ID_PREFIX):
                        sw_if_index_list, _ = get_app_sw_if_index_list(dev_id)
                        for _, sw_if_index in enumerate(sw_if_index_list):
                            vpp_attach_acls (sw_if_index,  global_ingress_keys, global_egress_keys,
                                             handler, firewall)
                            firewall.add_to_acl_interfaces(sw_if_index)
                    else:
                        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
                        vpp_attach_acls (sw_if_index,  global_ingress_keys, global_egress_keys,
                                         handler, firewall)
                        firewall.add_to_acl_interfaces(sw_if_index)
        except Exception as e:
            fwglobals.g.log.error(f"LAN ACL attachments failed. {str(e)}")
            handler.revert(e)
            raise

def setup_wan_acl_attachments(attachments, global_ingress_keys):
    """
    Setup ACL attachment to the WAN interfaces

    :param attachments: Interfaces and their ACL attachment values
    :type attachments: dict
    :param global_ingress_keys: Array of Global (All WAN interface) ACL keys to be\
        attached at the interface ingress
    :type global_ingress_keys: Array
    """
    with FwCfgMultiOpsWithRevert() as handler, FwFirewall() as firewall:
        try:
            # Process interface specific rules
            for dev_id, value in attachments.items():
                if value['ingress']:
                    # Add last default ACL as allow ALL
                    value['ingress'].append(DEFAULT_ALLOW_ID)
                    sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
                    vpp_attach_acls (sw_if_index, value['ingress'], None, handler, firewall)
                    firewall.add_to_acl_interfaces(sw_if_index)

            # Process global rules
            if global_ingress_keys:
                global_ingress_keys.append(DEFAULT_ALLOW_ID)
                interfaces = fwglobals.g.router_cfg.get_interfaces(type='wan')
                for interface in interfaces:
                    dev_id = interface['dev_id']
                    if not dev_id in attachments.keys():
                        sw_if_index = fwutils.dev_id_to_vpp_sw_if_index(dev_id)
                        vpp_attach_acls (sw_if_index, global_ingress_keys, None, handler, firewall)
                        firewall.add_to_acl_interfaces(sw_if_index)

        except Exception as e:
            fwglobals.g.log.error(f"WAN ACL attachments failed. {str(e)}")
            handler.revert(e)
            raise

def clear_acl_attachments(sw_if_index=None, firewall_object=None):
    """
    Clear ACL attachments on the given interface or all firewall interfaces

    :param sw_if_index: VPP identifier of the interface, defaults to None
    :type sw_if_index: Integer, optional
    :param firewall_object: Firewall class instance encapsulating the data stored in DB
    :type firewall_object: FwFirewall instance
    """
    with FwCfgMultiOpsWithRevert() as handler, \
        FwFirewall() if not firewall_object else firewall_object as firewall:
        try:
            if sw_if_index is None:
                for sw_if_index_str in firewall.get_acl_interfaces().keys():
                    sw_if_index = int(sw_if_index_str)
                    vpp_attach_acls (sw_if_index, None, None, handler, firewall)
                    firewall.remove_from_acl_interfaces(sw_if_index)
            else:
                if firewall.is_acl_interface (sw_if_index):
                    vpp_attach_acls (sw_if_index, None, None, handler, firewall)
                    firewall.remove_from_acl_interfaces(sw_if_index)
        except Exception as e:
            fwglobals.g.log.error(f"Detaching ACLs on interface failed. {str(e)}")
            handler.revert(e)
            raise

def setup_interface_acl_rules(is_add, match_dev_id, sw_if_index, if_type, handler, firewall):
    """
    Attach / Detach Firewall ACLs on the given interface. The function parses the
    rules and finds the ACLs that correspond to this given interface and then makes
    the call to attach/detach the ACLs on that interface.

    :param is_add: Flag to indicate attach or detach
    :type is_add: bool
    :param match_dev_id: Unique identifier that represents an interface
    :type match_dev_id: String
    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: Integer
    :param if_type: Type of interface i.e. wan or lan
    :type if_type: String
    :param handler: Instance handling the multi-config execution and revert
    :type handler: FwCfgMultiOpsWithRevert instance
    :param firewall: Firewall class instance encapsulating the data stored in DB
    :type firewall: FwFirewall instance
    """
    ingress_ids = []
    egress_ids = []
    if is_add:
        firewall_params = fwglobals.g.router_cfg.get_firewall_policy()
        if if_type == 'wan':
            inbound_rules = firewall_params.get('inbound')
            if not inbound_rules:
                return
            # Handle inbound rules
            wan_interfaces = fwglobals.g.router_cfg.get_interfaces(type=if_type)
            wan_dev_id_list = []
            for dev in wan_interfaces:
                dev_id = dev['dev_id']
                wan_dev_id_list.append (dev_id)
            if not match_dev_id in wan_dev_id_list:
                wan_dev_id_list.append(match_dev_id)

            for _, rules in inbound_rules.items():
                for rule in rules['rules']:
                    classification = rule.get('classification')
                    source = classification.get('source')
                    if not source:
                        continue
                    destination = classification.get('destination')
                    interface = destination.get('interface')
                    interfaces = [interface]\
                        if interface else destination.get('interfaces', wan_dev_id_list)
                    ingress_id = get_ingress_acl_key(rule)
                    for dev_id in interfaces:
                        if dev_id == match_dev_id:
                            ingress_ids.append(ingress_id)
            if ingress_ids:
                ingress_ids.append(DEFAULT_ALLOW_ID)
        else:
            outbound_rules = firewall_params.get('outbound')
            if not outbound_rules:
                return
            # Handle outbound rules
            lan_dev_id_list = []
            lan_interfaces = fwglobals.g.router_cfg.get_interfaces(type=if_type)
            for dev in lan_interfaces:
                dev_id = dev['dev_id']
                lan_dev_id_list.append (dev_id)
            _, app_dev_id_list = get_app_sw_if_index_list ()
            lan_dev_id_list.extend (app_dev_id_list)
            if not match_dev_id in lan_dev_id_list:
                lan_dev_id_list.append(match_dev_id)

            for rule in outbound_rules['rules']:
                action = rule.get('action')
                interfaces = action.get('interfaces', lan_dev_id_list)
                ingress_id = get_ingress_acl_key(rule)
                egress_id = get_egress_acl_key(rule)
                for dev_id in interfaces:
                    if dev_id == match_dev_id:
                        ingress_ids.append(ingress_id)
                        egress_ids.append(egress_id)
            if ingress_ids:
                ingress_ids.append(DEFAULT_ALLOW_ID)
            if egress_ids:
                egress_ids.append(DEFAULT_ALLOW_ID)

        vpp_attach_acls (sw_if_index, ingress_ids, egress_ids, handler, firewall)
        firewall.add_to_acl_interfaces(sw_if_index)
    else:
        clear_acl_attachments(sw_if_index, firewall_object=firewall)


def setup_firewall_rules (is_add, dev_id, vpp_if_name, sw_if_index, if_type, handler):
    """
    Entry function that is called from dynamic interface create/delete path.
    It setups/Clears up ACLs and NAT on the interface.

    :param is_add: Flag to indicate attach or detach
    :type is_add: bool
    :param dev_id: Unique identifier that represents an interface
    :type dev_id: String
    :param vpp_if_name: Name of the interface within VPP
    :type vpp_if_name: String
    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: Integer
    :param if_type: Type of interface i.e. wan or lan
    :type if_type: String
    :param handler: Instance handling the multi-config execution and revert
    :type handler: FwCfgMultiOpsWithRevert instance
    """
    with FwFirewall() as firewall:
        if not firewall.is_firewall_processed():
            return
        if not dev_id:
            # check if vpp_if_name is an application interface
            dev_id = vpp_if_name_to_app_firewall_dev_id(vpp_if_name)
        if not dev_id:
            dev_id = fwutils.vpp_if_name_to_dev_id (vpp_if_name)
        # Setup Firewall ACLs
        if if_type == 'lan' or if_type == 'wan':
            setup_interface_acl_rules (is_add, dev_id, sw_if_index, if_type, handler, firewall)
        # Setup Firewall NAT
        if if_type == 'wan':
            setup_wan_nat_rules (is_add, None, dev_id, handler)

def setup_firewall_context(is_add):
    """
    Set / Reset firewall state

    :param is_add: Flag to indicate the processing of firewall message
    :type is_add: bool
    """
    with FwFirewall() as firewall:
        if is_add:
            firewall.set_firewall_processed()
        else:
            firewall.reset()

def setup_firewall_context_cmd():
    """
    Generates the command to mark the firewall message as processed
    """
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']   = "setup_firewall_context"
    cmd['cmd']['module'] = "fwtranslate_add_firewall_policy"
    cmd['cmd']['descr']  = "Mark firewall as processed"
    cmd['cmd']['params'] = { 'is_add' : True}

    cmd['revert'] = {}
    cmd['revert']['func']   = "setup_firewall_context"
    cmd['revert']['module'] = "fwtranslate_add_firewall_policy"
    cmd['revert']['descr']  = "Unset firewall as processed"
    cmd['revert']['params'] = { 'is_add' : False}
    return cmd

def convert_dest_to_acl_rule_params(destination, dev_ids):
    """
    Convert the destination parameters mentioned in the inbound NAT rules to
    corresponding ACL parameters

    :param destination: Configuration in the 'destination' section of the inbound rule
    :type destination: dict
    :param dev_ids: Unique device identifier of the interfaces
    :type dev_ids: List of Strings
    """
    dest_rule_params = {}
    rule_array = []

    ports = destination.get('ports')
    if not ports:
        return None
    protocols = destination.get('protocols', ['tcp', 'udp'])

    for proto in protocols:
        if dev_ids:
            for dev_id in dev_ids:
                ip4_address = destination.get('ip4Address')
                if not ip4_address:
                    ip4_address = fwutils.get_interface_address(dev_id=dev_id)
                    if ip4_address:
                        ip4_address = ip4_address.split('/')[0]
                ip4_address = ip4_address + '/32' if ip4_address else '0.0.0.0/0'
                rule_array.append({
                    'ip': ip4_address,
                    'ports': ports,
                    'protocol': proto
                })
        else:
            rule_array.append({
                'ports': ports,
                'protocol': proto
            })

    dest_rule_params['ipProtoPort'] = rule_array
    return dest_rule_params


def firewall_handle_wan_addr_change(dev_id):
    """
    This function updates the ACL with the interface's updated IP address

    :param dev_id: Unique device identifier of the interface
    :type dev_id: String
    :raises Exception: Raises exception if the VPP API call failed
    """
    firewall_params = fwglobals.g.router_cfg.get_firewall_policy()
    if not firewall_params:
        return
    inbound_rules = firewall_params.get('inbound')
    if not inbound_rules:
        return
    for _, rules in inbound_rules.items():
        for rule in rules['rules']:
            ingress_id = None
            classification = rule.get('classification')
            destination = classification.get('destination')
            source = classification.get('source')
            interface = destination.get('interface')
            if not interface or interface != dev_id or not source:
                continue

            ingress_id = get_ingress_acl_key(rule)
            with FwFirewall() as firewall:
                acl_index = firewall.get_acl_id(ingress_id)

            dest_rule_params = convert_dest_to_acl_rule_params(destination, [dev_id])
            acl_rules, _, _ = fw_acl_command_helpers.generate_acl_rules_vpp_params\
                (source=source,
                 destination=dest_rule_params,
                 permit=True,
                 is_ingress=True,
                 acl_user_attr=None,
                 add_last_deny_all_src=True)
            rv = fwglobals.g.router_api.vpp_api.vpp.call('acl_add_replace',
                                                         acl_index=ctypes.c_uint(acl_index).value,
                                                         count=len(acl_rules),
                                                         r=acl_rules,
                                                         tag='')
            retval = getattr(rv, 'retval')
            if retval != 0:
                raise Exception(f'WAN IP4-Address change - ACL Update failed {rv}')
            else:
                fwglobals.log.info(f'WAN IP4-Address change - ACL Updated {rv}')


def add_firewall_policy(params):
    """
    Processes the firewall rules and generates corresponding commands
    Types of firewall rules
        1. Outbound rules - Attached on LAN interfaces
        2. Inbound rules - Attach on WAN ingress and create NAT mappings
        for 1:1 NAT, Port forward and Edge Access

    :param params: json/dict carrying the firewall message
    :return: Array of commands and each command is a dict
    """

    def process_inbound_rules(inbound_rules, firewall):

        cmd_list = []
        attachments = {}
        global_ingress_ids = []

        for _, rules in inbound_rules.items():
            for rule in rules['rules']:
                ingress_id = None
                classification = rule.get('classification')
                destination = classification.get('destination')
                source = classification.get('source')
                interface = destination.get('interface')
                dev_ids = [interface] if interface else []

                if source:
                    ingress_id = get_ingress_acl_key(rule)
                    dest_rule_params = convert_dest_to_acl_rule_params(destination, dev_ids)
                    cmd_list.extend(fw_acl_command_helpers.generate_add_acl_rule_commands(
                        acl_id=ingress_id,
                        source=source,
                        destination=dest_rule_params,
                        permit=True,
                        is_ingress=True,
                        add_last_deny_all_src=True
                    ))
                    firewall.add_acl_key (ingress_id)

                if dev_ids:
                    for dev_id in dev_ids:
                        if ingress_id:
                            if attachments.get(dev_id) is None:
                                    attachments[dev_id] = {}
                                    attachments[dev_id]['ingress'] =\
                                        copy.deepcopy(global_ingress_ids)
                            attachments[dev_id]['ingress'].append(ingress_id)
                else:
                    # Global rule
                    if ingress_id:
                        for dev_id in attachments.keys():
                            attachments[dev_id]['ingress'].append(ingress_id)
                        global_ingress_ids.append(ingress_id)

        return cmd_list, attachments, global_ingress_ids


    def process_outbound_rules(outbound_rules, firewall):

        cmd_list = []
        attachments = {}
        global_ingress_ids = []
        global_egress_ids = []

        for rule in outbound_rules['rules']:

            classification = rule.get('classification')
            if classification:
                destination = classification.get('destination')
                source = classification.get('source')
            else:
                destination = None
                source = None

            action = rule['action']
            permit = action['permit']
            ingress_id = get_ingress_acl_key(rule)

            # interfaces ['Array of LAN device ids] received from flexiManage
            dev_ids = action.get('interfaces', [])

            # skip rules for loopback interfaces we handle them in process_iptables_rules(outbound_rules)
            loopback_interface = False
            if dev_ids:
                for dev_id in dev_ids:
                    if fwutils.is_loopback_interface(dev_id=dev_id):
                        loopback_interface = True
            if loopback_interface:
                continue

            commands1 = fw_acl_command_helpers.generate_add_acl_rule_commands(
                acl_id=ingress_id,
                source=source,
                destination=destination,
                permit=permit,
                is_ingress=True
            )
            firewall.add_acl_key (ingress_id)

            egress_id = get_egress_acl_key(rule)
            commands2 = fw_acl_command_helpers.generate_add_acl_rule_commands(
                acl_id=egress_id,
                source=source,
                destination=destination,
                permit=permit,
                is_ingress=False
            )
            firewall.add_acl_key (egress_id)

            if not commands1 or not commands2:
                fwglobals.log.warning('Outbound firewall: Match conditions ' +
                    f'do not exist for rule : {rule}')
                continue

            cmd_list.extend(commands1)
            cmd_list.extend(commands2)

            if dev_ids:
                for dev_id in dev_ids:
                    if attachments.get(dev_id) is None:
                        attachments[dev_id] = {}
                        attachments[dev_id]['ingress'] = copy.deepcopy(global_ingress_ids)
                        attachments[dev_id]['egress'] = copy.deepcopy(global_egress_ids)
                    attachments[dev_id]['ingress'].append(ingress_id)
                    attachments[dev_id]['egress'].append(egress_id)
            else:
                # Global rule
                for dev_id in attachments.keys():
                    attachments[dev_id]['ingress'].append(ingress_id)
                    attachments[dev_id]['egress'].append(egress_id)
                global_ingress_ids.append(ingress_id)
                global_egress_ids.append(egress_id)

        return cmd_list, attachments, global_ingress_ids, global_egress_ids

    def process_iptables_rules(outbound_rules):

        cmd_list = []

        for rule_index, rule in enumerate(outbound_rules['rules']):

            classification = rule.get('classification')
            if classification:
                destination = classification.get('destination')
                source = classification.get('source')
            else:
                destination = None
                source = None

            action = rule['action']
            permit = action['permit']
            # interfaces ['Array of LAN device ids] received from flexiManage
            dev_ids = action.get('interfaces', [])

            for dev_id in dev_ids:
                if fwutils.is_loopback_interface(dev_id=dev_id):
                    try:
                        if_address = fwutils.get_interface_address(dev_id=dev_id)
                    except:
                        if_address = None

                    if if_address:
                        cmd_list.extend(fw_acl_command_helpers.add_iptables_rule(if_address, source, destination, permit))
                    else:
                        fwglobals.log.error(f'Outbound firewall: Cannot get ip address for interface {dev_id}')


        return cmd_list


    cmd_list = []

    with FwFirewall() as firewall:
        # Reset Firewall contexts
        firewall.reset()
        cmd_list.append(setup_firewall_context_cmd())

        # Add default Allow all ACLs
        # Traffic with no static/identity mapping shall get dropped by NAT lookup failure
        cmd_list.extend(fw_acl_command_helpers.generate_add_acl_rule_commands(
            acl_id=DEFAULT_ALLOW_ID,
            source=None,
            destination=None,
            permit=True,
            is_ingress=True
        ))
        firewall.add_acl_key (DEFAULT_ALLOW_ID)

        outbound_rules = params.get('outbound')
        if outbound_rules:
            outbound_cmd_list, lan_attachments, lan_global_ingress_keys,\
                lan_global_egress_keys = process_outbound_rules(outbound_rules, firewall)
            cmd_list.extend(outbound_cmd_list)

        inbound_rules = params.get('inbound')
        if inbound_rules:
            inbound_cmd_list, wan_attachments, wan_global_ingress_keys =\
                process_inbound_rules(inbound_rules, firewall)
            cmd_list.extend(inbound_cmd_list)

        #Command to transform acl keys to acl index using the command cache
        cmd_list.append(get_firewall_map_acl_keys_command())

        if outbound_rules:
            cmd_list.append(setup_lan_acl_attachments_cmd(lan_attachments,
                                                        lan_global_ingress_keys,
                                                        lan_global_egress_keys))

        if inbound_rules:
            cmd_list.append(setup_wan_acl_attachments_cmd(wan_attachments,
                                                        wan_global_ingress_keys))
            cmd_list.append(get_setup_wan_nat_command(inbound_rules))

        #Setup command to be executed for making iptables rules for linux interfaces
        if outbound_rules:
            cmd_list.extend(process_iptables_rules(outbound_rules))

    return cmd_list


def get_request_key(_params):
    """
    Mandatory function in all translate modules to return the message type handled

    :param params: Unused
    :return: String identifier representing the message
    """
    return 'add-firewall-policy'
