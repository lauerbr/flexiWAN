"""
Helper functions to convert classifications and actions into VPP ACL commands
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
import ctypes

import fw_input_validation
import fwglobals
import fwutils
from fw_traffic_identification import TRAFFIC_IMPORTANCE_VALUES, TRAFFIC_SERVICE_CLASS_VALUES

def get_vpp_acl_attach_params (sw_if_index, ingress_acls, egress_acls):
    """
    Get the VPP API's configuration parameters for attaching ACLs to an interface

    :param sw_if_index: VPP identifier of the interface
    :type sw_if_index: Integer
    :param ingress_acls: ACLS to be attached at the interface ingress
    :type ingress_acls: Array
    :param egress_acls: ACLS to be attached at the interface egress
    :type egress_acls: Array
    :return: Configuration parameter for setup and revert
    :rtype: dict, dict
    """
    acls = []
    if ingress_acls:
        acls.extend(ingress_acls)
    if egress_acls:
        acls.extend(egress_acls)

    config = {
        'api'    : 'acl_interface_set_acl_list',
        'params' : {
            'sw_if_index' : sw_if_index,
            'count'       : len (acls),
            'n_input'     : len (ingress_acls),
            'acls'        : acls
        }
    }
    revert_config = copy.deepcopy(config)
    revert_config['params']['count'] = 0
    revert_config['params']['n_input'] = 0
    revert_config['params']['acls'] = []
    return config, revert_config


def convert_match_to_acl_param(rule):

    ip_with_prefix = rule.get('ip')
    if not ip_with_prefix:
        ip_with_prefix = "0.0.0.0/0"

    ports = rule.get('ports')
    if ports:
        port_from, port_to = fwutils.ports_str_to_range(ports)
    else:
        port_from = 0
        port_to = 0xffff
    protocols = rule.get('protocols')
    if protocols is None:
        protocol_single = rule.get('protocol')
        if protocol_single:
            protocols = [protocol_single]
    protocols_map = []
    if protocols:
        for protocol in protocols:
            protocols_map.append(fwutils.proto_map[protocol])
    elif ports:
        protocols_map.append(fwutils.proto_map['tcp'])
        protocols_map.append(fwutils.proto_map['udp'])

    return ip_with_prefix, port_from, port_to, protocols_map if protocols_map else None


def _generate_vpp_acl_rules_from_matches(source_match, dest_match, permit, is_ingress, acl_user_attr):
    """
    Generates a list of VPP ACL rules from given source and destination match parameters.

    :param source_match: A dictionary representing the source match criteria, including IP, port, and protocol information.
    :type source_match: dict
    :param dest_match: A dictionary representing the destination match criteria, including IP, port, and protocol information.
    :type dest_match: dict
    :param permit: Boolean flag indicating whether the traffic should be allowed (True) or denied (False).
    :type permit: bool
    :param is_ingress: Boolean flag indicating if the rule applies to ingress traffic. If None, rules are generated for both directions.
    :type is_ingress: bool
    :param acl_user_attr: A dictionary of user-defined attributes to be attached to the generated VPP ACL rules.
    :type acl_user_attr: dict
    :return: A list of dictionaries, each representing a VPP ACL rule.
    :rtype: list
    """
    rules = []
    src_ip_with_prefix, src_port_from, src_port_to, src_proto =\
        convert_match_to_acl_param(source_match)
    dst_ip_with_prefix, dest_port_from, dest_port_to, dst_proto =\
        convert_match_to_acl_param(dest_match)
    if dst_proto is None and src_proto is not None:
        dst_proto = src_proto
    elif dst_proto is None:
        dst_proto = [0]

    # Protocol is not expected to be present in a valid source match
    # Check and log source and destination protocol mismatch
    if src_proto:
        src_proto.sort()
        dst_proto.sort()
        if src_proto != dst_proto:
            fwglobals.log.warning('Mismatch between src (%s) and dest (%s) protocol fields'
                                    % (src_proto, dst_proto))

    for proto in dst_proto:
        if proto == fwutils.proto_map['icmp']:
            sport_from = dport_from = 0
            sport_to = dport_to = 0xffff
        else:
            sport_from = src_port_from
            sport_to = src_port_to
            dport_from = dest_port_from
            dport_to = dest_port_to

        if is_ingress is None or is_ingress:
            rules.append({'is_permit': int(permit is True),
                            'is_ipv6': 0,
                            'src_prefix': src_ip_with_prefix,
                            'dst_prefix': dst_ip_with_prefix,
                            'proto': proto,
                            'srcport_or_icmptype_first': sport_from,
                            'srcport_or_icmptype_last': sport_to,
                            'dstport_or_icmpcode_first': dport_from,
                            'dstport_or_icmpcode_last': dport_to,
                            'acl_user_attr': acl_user_attr})

        if is_ingress is None or not is_ingress:
            rules.append({'is_permit': int(permit is True),
                            'is_ipv6': 0,
                            'src_prefix': dst_ip_with_prefix,
                            'dst_prefix': src_ip_with_prefix,
                            'proto': proto,
                            'srcport_or_icmptype_first': dport_from,
                            'srcport_or_icmptype_last': dport_to,
                            'dstport_or_icmpcode_first': sport_from,
                            'dstport_or_icmpcode_last': sport_to,
                            'acl_user_attr': acl_user_attr})
    return rules


def _is_match_unique(match1, match2):

    if match1 and match2:
        ip_with_prefix1, port_from1, port_to1, _ =\
            convert_match_to_acl_param(match1)
        ip_with_prefix2, port_from2, port_to2, _ =\
            convert_match_to_acl_param(match2)
        if ((ip_with_prefix1 == ip_with_prefix2) and (port_from1 == port_from2) and
                (port_to1 == port_to2)):
            return 0
    return 1


def generate_acl_rules_vpp_params(source, destination, permit, is_ingress, acl_user_attr, add_last_deny_all_src=False):
    """
    Generates VPP ACL rules based on source and destination match criteria.

    :param source: The source definition for traffic rules. Can include traffic IDs, static IP/port, or any match.
    :type source: dict or None
    :param destination: The destination definition for traffic rules. Can include traffic IDs, traffic tags,
                        static IP/port, or any match.
    :type destination: dict or None
    :param permit: Flag to indicate whether traffic should be permitted or denied.
    :type permit: bool
    :param is_ingress: Flag to specify whether the rules apply to ingress traffic.
    :type is_ingress: bool
    :param acl_user_attr: Metadata or attributes to associate with the ACL rules.
    :type acl_user_attr: dict
    :param add_last_deny_all_src: Flag to add a final deny-all rule for unmatched traffic at the end of the ACL list.
    :type add_last_deny_all_src: bool
    :return: A tuple containing:
             - `acl_rules`: List of ACL rules in VPP-compatible format.
             - `tags_based`: Boolean indicating whether rules were generated based on traffic tags.
             - `app_ids`: List of application IDs associated with the rules.
    :rtype: tuple[list[dict], bool, list]
    """
    def _get_traffic_rules(traffic_id=None, traffic_tags=None):
        if traffic_id:
            return fwglobals.g.traffic_identifications.get_traffic_rules(traffic_id, None, None, None)
        elif traffic_tags:
            category      = traffic_tags.get('category')
            service_class = traffic_tags.get('serviceClass')
            importance    = traffic_tags.get('importance')
            return fwglobals.g.traffic_identifications.get_traffic_rules(None, category, service_class, importance)
        return [], []

    acl_rules      = []
    dest_matches   = []
    source_matches = []
    any_match      = {}
    tags_based     = False
    app_ids        = []

    if destination:
        # Combination of "trafficId" and "trafficTags" is not allowed, as well as the combination of
        # "trafficTags" and "ipProtoPort" (static IPs).
        # However, the combination of "trafficId" and "ipProtoPort" (static IPs) is allowed.
        # This allows the possibility of duplication, as the query
        # for "trafficId" rules may return the same IPs that are already included in the static IPs list.
        # This potential duplication is addressed later in the function.
        #
        traffic_id = destination.get('trafficId')
        traffic_tags = destination.get('trafficTags')
        rules, application_ids = _get_traffic_rules(traffic_id, traffic_tags)
        dest_matches.extend(rules)
        app_ids.extend(application_ids)

        static_rules = destination.get('ipProtoPort')
        if static_rules:
            dest_matches.extend(static_rules if isinstance(static_rules, list) else [static_rules])
    else:
        dest_matches.append(any_match)

    if source:
        traffic_id = source.get('trafficId')
        if traffic_id:
            source_matches, application_ids = _get_traffic_rules(traffic_id)
            app_ids.extend(application_ids)
        else:
            custom_rule = source.get('ipPort')
            source_matches.append(custom_rule)
    else:
        source_matches.append(any_match)

    used_rules = set()
    for dest_match in dest_matches:
        source_match_prev = None
        for source_match in source_matches:
            if _is_match_unique(source_match, source_match_prev):
                rules = _generate_vpp_acl_rules_from_matches(source_match, dest_match, permit, is_ingress, acl_user_attr)

                # Deduplicate rules using a "set()" for efficient lookups.
                # Since "rule" is unhashable due to being a nested object, "repr" is used to create a consistent string representation,
                # assuming "rules" have a consistent format and key order.
                #
                for rule in rules:
                    obj_str = repr(rule)
                    if obj_str not in used_rules:
                        acl_rules.append(rule)
                        used_rules.add(obj_str)

                source_match_prev = source_match

    if add_last_deny_all_src:
        last_acl, _, _ = generate_acl_rules_vpp_params(
            source=None,
            destination=destination,
            permit=False,
            is_ingress=is_ingress,
            acl_user_attr=acl_user_attr,
            add_last_deny_all_src=False  # Prevent recursion
        )
        if not last_acl:
            raise Exception(f"Generated default deny ACL rule is empty for destination: {destination}")
        acl_rules.extend(last_acl)

    # Convert rules back to list of dicts
    return acl_rules, tags_based, list(set(app_ids))


def handle_app_fqdn_change(traffic_id, ports, protocols, prev_ip_addresses, ip_addresses):
    # 1. update the ips in the applications database
    new_app_ip_addresses = list(map(lambda ip: { 'ip': f'{ip}/32', 'ports': ports, 'protocols': protocols }, ip_addresses))
    old_app_ip_addresses = list(map(lambda ip: { 'ip': f'{ip}/32', 'ports': ports, 'protocols': protocols }, prev_ip_addresses))
    fwglobals.g.traffic_identifications.update_traffic_identification_ips(traffic_id, new_app_ip_addresses, old_app_ip_addresses)

    # 2. get all acl indexes for the given application
    acl_indexes = fwglobals.g.traffic_identifications.get_traffic_vpp_acl_indexes(traffic_id)
    if not acl_indexes:
        fwglobals.log.error(f'It is not expected to call this function without ACL indexes in the DB for {traffic_id}')
        raise Exception('Failed to handle FQDN App identification change')

    # 3. update each acl with the updated IPs
    for acl_index, acl_parameters in acl_indexes.items():
        acl_rules, _, _ = generate_acl_rules_vpp_params(**acl_parameters)
        fwglobals.g.router_api.vpp_api.vpp.call(
            'acl_add_replace',
            acl_index=ctypes.c_uint(acl_index).value,
            count=len(acl_rules),
            r=acl_rules,
            tag=''
        )

def generate_add_acl_rule_commands(
        acl_id,
        source,
        destination,
        permit,
        is_ingress,
        add_last_deny_all_src=False,
        acl_user_attr=None,
        app_id=None
    ):
    """ Function that encapsulates call to generation of ACL command and its params

    :param acl_id: String identifier representing the ACL
    :param source: json/dict message representing the source
    :param destination: json/dict message representing the destination
    :param permit: Boolean representing the action
    :param is_ingress: Boolean representing is ingress or not
    :param add_last_deny_all_src: Flag to indicate if a last deny all sources rule to be auto added
    :param acl_user_attr: User attributes to be attached to this rule
    :param app_id: String representing the application ID of the ACL
    :return: Dict representing the command. None can be returned if the given
             traffic tags based match does not have a valid match in the app/traffic ID DB
    """

    cmd_list = []

    acl_rules, tags_based, app_ids = generate_acl_rules_vpp_params(
        source=source,
        destination=destination,
        permit=permit,
        is_ingress=is_ingress,
        acl_user_attr=acl_user_attr,
        add_last_deny_all_src=add_last_deny_all_src
    )

    if app_id and app_id not in app_ids:
        app_ids.append(app_id)

    if not acl_rules:
        if app_ids:
            # Application can be created with no rules in case of FQDN.
            # Just log it and continue
            fwglobals.log.info(f'ACL rules list is empty for application Ids: {app_ids}')
        else:
            fwglobals.log.warning('ACL rules list is empty. Check if traffic tags has a valid match.' +
                                    f'Source: {source} Destination: {destination}')
            if tags_based:
                # It may not be fatal if traffic tags based classification does not exist
                # Allow the caller to make the decision
                return []
            else:
                raise Exception ('Generated ACL rule is empty')

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']  = "call_vpp_api"
    cmd['cmd']['descr'] = "Add Firewall ACL"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
                            'api': "acl_add_replace",
                            'args': {
                                'acl_index': ctypes.c_uint(-1).value,
                                'count': len(acl_rules),
                                'r': acl_rules,
                                'tag': ''
                            }
                        }
    cmd['cmd']['cache_ret_val'] = ('acl_index', acl_id)
    cmd['revert'] = {}
    cmd['revert']['func']  = "call_vpp_api"
    cmd['revert']['descr'] = "Remove Firewall ACL"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
            'api':  "acl_del",
            'args': {
                'substs': [ { 'add_param': 'acl_index', 'val_by_key': acl_id } ]
            }
    }
    cmd_list.append(cmd)

    for app_id in app_ids:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "add_remove_app_vpp_acl_index"
        cmd['cmd']['object'] = "fwglobals.g.traffic_identifications"
        cmd['cmd']['descr']  = f"Save ACL index for {app_id} in the Traffic Identification DB"
        cmd['cmd']['params'] = {
            'is_add': True,
            'traffic_id': app_id,
            'acl_parameters': {
                'source': source,
                'destination': destination,
                'permit': permit,
                'is_ingress': is_ingress,
                'acl_user_attr': acl_user_attr,
                'add_last_deny_all_src': add_last_deny_all_src
            },
            'substs': [{ 'add_param': 'acl_index', 'val_by_key': acl_id }]
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "add_remove_app_vpp_acl_index"
        cmd['revert']['object'] = "fwglobals.g.traffic_identifications"
        cmd['revert']['descr']  = f"Remove ACL index for {app_id} from the Traffic Identification DB"
        cmd['revert']['params'] = {
            'is_add': False,
            'traffic_id': app_id,
            'substs': [{ 'add_param': 'acl_index', 'val_by_key': acl_id }]
        }
        cmd_list.append(cmd)
    return cmd_list


def build_acl_user_attributes (user_value, service_class, importance):
    """
    Build user attributes structure that can be attached to ACL rule.
    The attributes can be used to encode additional user values to be associated with this rule.

    :param user_value: User value to be attached to the rule
    :type user_value: Integer
    :param service_class: Service class attribute to be attached to the rule
    :type service_class: string
    :param importance: Importance attribute to be attached to the rule
    :type importance: string
    :return: user attribute structure that can be passed to the VPP add acl API
    :rtype: dict
    """
    if user_value:
        acl_user_attr = {
            'user_value': user_value
        }
    else:
        service_class = TRAFFIC_SERVICE_CLASS_VALUES.get(service_class)
        importance = TRAFFIC_IMPORTANCE_VALUES.get(importance)
        acl_user_attr = {
            'attributes': {
                'service_class': service_class,
                'importance': importance
            }
        }
    return acl_user_attr

protocol_map = {0 : 'any', 1 : 'icmp', 6 : 'tcp', 17 : 'udp'}

def build_iptables_rule_cmd(iptable, proto_id, dst_ip, dport_first, dport_last,
                            src_ip, sport_first, sport_last, is_permit):

    """
    Build a command to create iptables rule according to configured policy.

    :param iptable: iptable name, like INPUT, OUTPUT, etc
    :param proto_id: protocol id from protocol_map dictionary
    :param dst_ip: destination prefix
    :param dstport_or_icmpcode_first: beginning of destination port or ICMP4/6 code range
    :param dstport_or_icmpcode_last: end of destination port or ICMP4/6 code range
    :param src_prefix: source prefix
    :param srcport_or_icmptype_first: beginning of source port or ICMP4/6 type range
    :param srcport_or_icmptype_last: end of source port or ICMP4/6 type range
    :param is_permit - deny (0), permit (1)
    :return: Dict representing the commands.
    """

    # The values come from firewall rules received from flexiManage and are
    # used in shell command, so validate them.
    for ip in [dst_ip, src_ip]:
        if ip and not fw_input_validation.is_valid_network(ip):
            raise ValueError(f"build_iptables_rule_cmd: invalid IP/network {ip!r}")
    for port in [dport_first, dport_last, sport_first, sport_last]:
        if not fw_input_validation.is_valid_int(port, 0, 0xffff):
            raise ValueError(f"build_iptables_rule_cmd: invalid port {port!r}")
    if not fw_input_validation.is_shell_safe_word(str(iptable)):
        raise ValueError(f"build_iptables_rule_cmd: invalid iptable {iptable!r}")

    proto = f"-p {protocol_map[proto_id]}" if proto_id != 0 else ""

    dst = f"-d {dst_ip}" if dst_ip and dst_ip != '0.0.0.0/0' else ""

    dport = f"--dport {dport_first}:{dport_last}" if dport_first > 0 or dport_last < 0xffff else ""

    src = f"-s {src_ip}" if src_ip and src_ip != '0.0.0.0/0' else ""

    sport = f"--sport {sport_first}:{sport_last}" if sport_first > 0 or sport_last < 0xffff else ""

    action = "-j ACCEPT" if is_permit else "-j DROP"

    linux_cmd = f'sudo iptables -A {iptable} {proto} {dst} {dport} {src} {sport} {action}'
    linux_check_cmd = f'sudo iptables -C {iptable} {proto} {dst} {dport} {src} {sport} {action}'
    linux_revert_cmd = f'sudo iptables -D {iptable} {proto} {dst} {dport} {src} {sport} {action} &> /dev/null'

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "exec"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   = f"set firewall rules to iptables"
    cmd['cmd']['params']  = {'cmd': f'{linux_check_cmd} || {linux_cmd}'}
    cmd['revert'] = {}
    cmd['revert']['func']    = "exec"
    cmd['revert']['module']  = "fwutils"
    cmd['revert']['descr']   = f"remove firewall rules from iptables"
    cmd['revert']['params']  = {'cmd': linux_revert_cmd}

    return cmd


def generate_iptables_rules(if_address, acl_rules):
    """ Function that encapsulates call to generation of iptables command and its params

    :param if_address: ipaddress of interface
    :param acl_rules: dict with acl rules
    :return: Dict representing the command. None can be returned if the given
             traffic tags based match does not have a valid match in the app/traffic ID DB
    """

    cmd_list = []

    for acl_rule in acl_rules:

        cmd = build_iptables_rule_cmd(  iptable = "INPUT",
                                        proto_id = acl_rule.get('proto', 0),
                                        dst_ip = if_address,
                                        dport_first = acl_rule.get('dstport_or_icmpcode_first', 0),
                                        dport_last = acl_rule.get('dstport_or_icmpcode_last', 0xffff),
                                        src_ip = acl_rule.get('src_prefix', '0.0.0.0/0'),
                                        sport_first = acl_rule.get('srcport_or_icmptype_first', 0),
                                        sport_last = acl_rule.get('srcport_or_icmptype_last', 0xffff),
                                        is_permit = acl_rule.get('is_permit', 0))

        cmd_list.append(cmd)

        cmd = build_iptables_rule_cmd(  iptable = "OUTPUT",
                                        proto_id = acl_rule.get('proto', 0),
                                        dst_ip = acl_rule.get('src_prefix', '0.0.0.0/0'),
                                        dport_first = acl_rule.get('srcport_or_icmptype_first', 0),
                                        dport_last = acl_rule.get('srcport_or_icmptype_last', 0xffff),
                                        src_ip = if_address,
                                        sport_first = acl_rule.get('dstport_or_icmpcode_first', 0),
                                        sport_last = acl_rule.get('dstport_or_icmpcode_last', 0xffff),
                                        is_permit = acl_rule.get('is_permit', 0))

        cmd_list.append(cmd)

    return cmd_list


def add_iptables_rule(if_address, source, destination, permit):
    """ Function that encapsulates call to generation of iptables command and its params

    :param if_address: ipaddress of interface
    :param source: json/dict message representing the source
    :param destination: json/dict message representing the destination
    :param permit: json/dict message representing the action
    :return: Dict representing the command. None can be returned if the given
             traffic tags based match does not have a valid match in the app/traffic ID DB
    """

    cmd_list = []

    acl_rules, tags_based, _ = generate_acl_rules_vpp_params\
                            (source, destination, permit, False, None)

    if not acl_rules:
        fwglobals.log.warning('Generated iptables rule is empty. ' +
            'Check if traffic tags has a valid match.' +
            'Source: %s Destination: %s' % (source, destination))
        if tags_based:
            # It may not be fatal if traffic tags based classification does not exist
            # Allow the caller to make the decision
            return []
        else:
            raise Exception ('Generated iptables rule is empty')

    cmd_list = generate_iptables_rules(if_address, acl_rules)

    return cmd_list

def exec_iptables_rules(is_add, if_address, source, destination, permit):
    """ Function that encapsulates call to execute of iptables command and its params

    :param is_add: Flag to indicate setup or delete config
    :param if_address: ipaddress of interface
    :param source: json/dict message representing the source
    :param destination: json/dict message representing the destination
    :param permit: json/dict message representing the action
    :return: None
    """

    cmd_list = add_iptables_rule(if_address, source, destination, permit)

    for cmd in cmd_list:
        if is_add:
            linux_cmd = cmd.get('cmd', {}).get('params', {}).get('cmd')
            if linux_cmd:
                (ok, output) = fwutils.exec(linux_cmd)
                if not ok:
                    fwglobals.log.warning(f'Failed to apply iptables rule {linux_cmd}: {output}')
        else:
            linux_revert_cmd = cmd.get('revert', {}).get('params', {}).get('cmd')
            if linux_revert_cmd:
                (ok, output) = fwutils.exec(linux_revert_cmd)
                if not ok:
                    fwglobals.log.warning(f'Failed to apply iptables rule {linux_revert_cmd}: {output}')
    return
