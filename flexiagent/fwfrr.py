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

import ast
import json
import os
import subprocess
import tempfile

import fwglobals
import fwutils
import fw_input_validation as validate
from fwobject import FwObject


class FwFrr(FwObject):
    """This is object that encapsulates configuration of FRR.
    """
    def __init__(self, db_file, fill_if_empty=True):
        FwObject.__init__(self)

        # The DB contains:
        # db['ospf']       - the OSPF configuration

        self.db = fwglobals.g.create_sqlite_dict(db_file)

        if not fill_if_empty:
            return

        if not 'ospf' in self.db:
            self.db['ospf'] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def finalize(self):
        """Destructor
        """
        return None

    def clean(self):
        """Clean DB
        """
        self.db['ospf'] = {}

    def dumps(self):
        """Prints content of database into string
        """
        db_keys = sorted(self.db.keys())                    # The key order might be affected by dictionary content, so sort it
        dump = [ { key: self.db[key] } for key in db_keys ] # We can't json.dumps(self.db) directly as it is SqlDict and not dict
        return json.dumps(dump, indent=2, sort_keys=True)

    def ospf_network_add(self, dev_id, address=None, area='0.0.0.0'):
        """Adds network to configuration of FRR, which should be published by OSPF.
        We use addresses of LAN interfaces to describe such networks. As a result,
        the branch networks are exchanged between flexiEdge devices by OSPF over
        tunnels, so two or more company branches become to be visible one to each other.

        :param dev_id:  The DEV-ID of the interface, network of which should be added to FRR OSPF.
        :param address: The address of network to be added. It will appear as "network {address} area {area}" record in ospfd.conf.
        :param area:    The area, which the added network belongs to.

        :returns: True on success, (False, err_str) tuple otherwise
        """
        ospf         = self.db['ospf']
        ospf_network = ospf.get(dev_id, {}).get('network')
        if ospf_network:
            self.log.error(f"ospf_network_add({dev_id}): network for '{dev_id}' exists: {str(ospf_network)}")
            return (False, f"failed to add OSPF network for {dev_id}")

        if not address:
            address = fwutils.get_interface_address(dev_id=dev_id)

        if address:     # update FRR only if interface has IP (DHCP/cable is plugged/etc)
            ret, err_str =  self.run_ospf_add(address, area)
            if not ret:
                self.log.error(f"ospf_network_add({dev_id}): failed to update frr: {err_str}")
                return (False, f"failed to add OSPF network for {dev_id}")

        if not dev_id in ospf:
            ospf[dev_id] = {}
        ospf_network = { 'address': address, 'area': area }
        ospf[dev_id].update({'network': ospf_network})
        self.db['ospf'] = ospf    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        self.log.debug(f"ospf_network_add({dev_id}): {str(ospf_network)}")
        return True

    def ospf_network_remove(self, dev_id):
        """Removes network to be published by OSPF from the FRR configuration.

        :param dev_id:  The DEV-ID of the interface, network of which should be removed.

        :returns: None
        """
        ospf         = self.db['ospf']
        ospf_network = ospf.get(dev_id, {}).get('network')
        if not ospf_network:
            self.log.debug(f"ospf_network_remove({dev_id}): there is no existing network for '{dev_id}'")
            return

        if ospf_network['address']:  # update FRR only if interface has IP
            # For bridges, each interface has a record in the OSPF database, containing the bridge's address.
            # However, in FRR configuration, the network appears only once.
            # If two modify-interfaces are on the same bridge,
            # and we execute two remove-interfaces (due to "aggregated" request with two "modify-interface"),
            # the second remove throws an error because the network is already deleted from OSPF but it will have a record in our DB.
            #
            # For bridge interfaces, ensure OSPF is not removed when there are other
            # interfaces under this bridge network address
            #
            # To resolve above issues:
            # For bridge interfaces, before removal from OSPF configuration,
            # check if no other interfaces are under the same bridge
            bridged_addr = fwutils.is_bridged_interface(dev_id)
            if bridged_addr:
                bridged_interfaces = fwglobals.g.router_cfg.get_interfaces(ip=ospf_network['address'])
            if not bridged_addr or len(bridged_interfaces) == 1:
                ret, err_str = self.run_ospf_remove(ospf_network['address'], ospf_network['area'])
                if not ret:
                    self.log.excep(f"ospf_network_remove({dev_id}): failed to update frr: {err_str}")

        self.log.debug(f"ospf_network_remove({dev_id}): {str(ospf_network)}")
        del ospf[dev_id]['network']
        self.db['ospf'] = ospf    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict

    def ospf_network_update(self, dev_id, new_address):
        """Updates network to be published by OSPF. The network is identified by
        the interface attached to this network. In turn, the interface is identified
        by dev-id.
            Note the update might remove network from FRR, if the new value
        of network is None.
            To remove network completely, i.e. from both FRR and from the self.db,
        you should call the ospf_network_remove().

        :param dev_id:      The DEV-ID of the interface, network of which should be updated.
        :param new_address: The new address of the network.

        :returns: True on success, False otherwise
        """
        ospf         = self.db['ospf']
        ospf_network = ospf.get(dev_id, {}).get('network')
        if not ospf_network:
            self.log.error(f"ospf_network_update({dev_id}): there is no existing network for '{dev_id}'")
            return False

        # Firstly remove the old network if exists
        #
        area        = ospf_network['area']
        old_address = ospf_network['address']
        if old_address:
            ret, err_str = self.run_ospf_remove(old_address, area)
            if not ret:
                self.log.excep(f"ospf_network_update({dev_id}): failed to remove old network '{old_address}' from frr: {err_str}")

        # Now update new address.
        # If new address was provided, update FRR. Otherwise update database only.
        #
        if new_address:
            ret, err_str = self.run_ospf_add(new_address, area)
            if not ret:
                self.log.excep(f"ospf_network_update({dev_id}): failed to add new network '{new_address}' to frr: {err_str}")
                new_address = None

        ospf_network['address'] = new_address
        self.db['ospf'] = ospf    # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        self.log.debug(f"ospf_network_update({dev_id}): '{old_address}' -> '{new_address}'")

    def translate_bgp_neighbor_to_frr_commands(self, neighbor,  global_keepalive_timer=None, global_hold_timer=None):
        ip = neighbor.get('ip')
        remote_asn = neighbor.get('remoteAsn')
        password = neighbor.get('password')
        keepalive_interval = neighbor.get('keepaliveInterval', global_keepalive_timer)
        hold_interval = neighbor.get('holdInterval', global_hold_timer)
        ebgp_multihop = neighbor.get('multiHop', 1) # 1 is the BGP default

        # The values are used to build FRR (vtysh) commands, so validate them
        # to prevent injection of other commands.
        #
        validate.ensure_ip(ip, 'BGP neighbor IP')
        if remote_asn not in ['internal', 'external']:
            validate.ensure_int(remote_asn, 'BGP neighbor remote ASN', 0, 4294967295)
        validate.ensure_int(ebgp_multihop, 'BGP neighbor multihop', 1, 255)
        if password:
            validate.ensure_safe_string(password, 'BGP neighbor password', forbidden='"\'`$\\ ')
        if keepalive_interval and hold_interval:
            validate.ensure_int(keepalive_interval, 'BGP keepalive interval', 0, 65535)
            validate.ensure_int(hold_interval, 'BGP hold interval', 0, 65535)

        commands = [
            f'neighbor {ip} remote-as {remote_asn}',

            # Allow peering between directly connected eBGP peers using loopback addresses.
            f'neighbor {ip} disable-connected-check',
            f'neighbor {ip} ebgp-multihop {ebgp_multihop}',
        ]

        # If VRRP is in a backup state, BGP configuration should be adjusted to reflect that.
        # To do this we just reset the VRPP state, thus enforcing VRRP thread ("_sync_vrrp_state") to do the job.
        #
        if fwglobals.g.router_api.vrrp_state == 'BACKUP':
            fwglobals.g.router_api.vrrp_state = None

        if password:
            commands.append(f'neighbor {ip} password {password}')

        if keepalive_interval and hold_interval:
            commands.append(f'neighbor {ip} timers {keepalive_interval} {hold_interval}')

        # "custom" includes a list of commands for FRR CLI (vtysh) after each neighbor
        custom_commands = neighbor.get('custom', [])
        for custom_command in custom_commands:
            fwutils.frr_validate_command(custom_command)
            commands.append(custom_command)

        return commands

    def run_ospf_remove(self, address, area, skip_if_not_exists=False, wait_after=None):
        if skip_if_not_exists:
            frr_json_output = subprocess.check_output('vtysh -c "show ip ospf interface json"', shell=True).decode().strip()
            #{
            #   "interfaces":{
            #       "vpp4":{
            #           ...
            #           "ipAddress":"112.1.1.1",
            #           "ipAddressPrefixlen":24,
            #           ...
            output_json = json.loads(frr_json_output).get('interfaces', {})
            network_exists = [ifc for ifc, details in output_json.items() if f'{details.get("ipAddress")}/{details.get("ipAddressPrefixlen")}' == address]
            if not network_exists:
                self.log.debug(f"run_ospf_remove({address}, {area}): removal command is unnecessary. Network non-existent")
                return (True, None)

        ret, err_str = fwutils.frr_vtysh_run(["router ospf", f"no network {address} area {area}"], wait_after=wait_after)
        return ret, err_str

    def run_ospf_add(self, address, area):
        # If VRRP is in a backup state, OSPF configuration should be adjusted to reflect that. 
        # To do this we just reset the VRPP state, thus enforcing VRRP thread ("_sync_vrrp_state") to do the job.
        #
        if fwglobals.g.router_api.vrrp_state == 'BACKUP':
            fwglobals.g.router_api.vrrp_state = None

        ret, err_str = fwutils.frr_vtysh_run(["router ospf", f"network {address} area {area}"])
        return ret, err_str

    def run_bgp_remove_network(self, local_asn, address):
        ret, err_str = fwutils.frr_vtysh_run([f"router bgp {local_asn}", 'address-family ipv4 unicast', f"no network {address}"])
        return ret, err_str

    def run_bgp_add_network(self, local_asn, address):
        ret, err_str = fwutils.frr_vtysh_run([f"router bgp {local_asn}", 'address-family ipv4 unicast', f"network {address}"])
        return ret, err_str

    def translate_route_map_to_frr_commands(self, name, description, action, seq, match_acl_name=None, next_hop=None, custom_commands=[]):
        frr_action = 'permit' if action == 'allow' else 'deny'
        if description:
            validate.ensure_safe_string(description, 'routing filter description', forbidden='"`')
        if next_hop:
            validate.ensure_ip(next_hop, 'routing filter next hop')
        for custom_command in custom_commands:
            fwutils.frr_validate_command(custom_command)
        commands = [
            f'route-map {name} {frr_action} {seq}',
            f'  description {description}',
        ]

        if match_acl_name:
            commands.append(f'  match ip address prefix-list {match_acl_name}')

        if next_hop:
            commands.append(f'  set ip next-hop {next_hop}')
        
        # "custom" includes a list of commands for FRR CLI (vtysh) under the "route-map"
        for custom_command in custom_commands:
            commands.append(f'  {custom_command}')

        return commands

    def translate_routing_filter_to_frr_commands(self, name, description, rules):
        '''Convert flexiManage routing filter params to FRR add and remove commands.

        :param name:         name of the routing filter
        :param description:  description of the routing filter
        :param rules:        list of rules

        Example of "rules":
        {
            "route":"0.0.0.0/0",
            "action":"allow",
            "nextHop":"",
            "priority":0
        },
        {
            "route":"8.8.8.8/24",
            "action":"allow",
            "nextHop":"",
            "priority":1
        },
        {
            "route":"5.5.5.5/32",
            "action":"deny",
            "nextHop":"",
            "priority":2
        },
        {
            "route":"5.5.5.5/24",
            "action":"allow",
            "nextHop":"",
            "priority":3
        }

        :returns: tuple with two lists - add commands and remove commands.

        The logic to convert rules to route-maps and access-lists is as follows:

        First, we sort the "rules" by "priority" field. As written above, multiple route-map with the same name
        can be configured. Route that is "matched" early in the chain
        will not continue to the next steps, but will be permitted/denied according to the policy.

        Then, we loop over the rules, one by one and creates groups of routes that have the same set of actions.
        Route has "action" (allow, deny), and "nextHop" (ipv4 address or empty).
        When looping on the routes, we group all routes that their "action" and "nextHop" are the same.

        Note, the order set by the user is important.
        Therefore, a route will not always be pushed to the same group even though it has the same set of actions.
        For example in the rules above, the 5.5.5.5/24 and 8.8.8.8/24 have the same set of actions.
        But we can't group them together since, if we will put the 8.8.8.8/24 before 8.8.8.8/32,
        the 8.8.8.8/32 will bot be denied since it will be matched fy the first rule.

        Then, we loop over the groups and we create access-lists and route-maps for each group.

        We do not create route-map for a group that has same set of actions as the default route.
        '''
        add_commands    = []
        remove_commands = []

        default_rule = None

        rules = sorted(rules, key=lambda x: x['priority'])

        groups = {}
        tmp_group_key = None
        tmp_group_routes = []
        for rule in rules:
            route, action, next_hop, custom_list = rule.get('route'), rule.get('action'), rule.get('nextHop'), rule.get('custom', [])

            validate.ensure_network(route, 'routing filter route')

            if route == '0.0.0.0/0': # don't create group for default route, we always add it at the end.
                default_rule = (route, action, next_hop, custom_list)
                continue

            route_group_key = f'{action}_{next_hop}_{str(custom_list)}' # "action" and "next_hop" are the key to check if routes should be groups.

            # first time, create a candidate group with no check
            if not tmp_group_key:
                tmp_group_key = route_group_key
                tmp_group_routes.append(route)
                continue

            # if route can be grouped with another route
            if route_group_key == tmp_group_key:
                tmp_group_routes.append(route)
                continue

            # At this point, we need to pack the temporary group into the list of groups,
            # and create a new temporary group
            groups[f'{len(groups)}_{tmp_group_key}'] = tmp_group_routes

            tmp_group_key = route_group_key
            tmp_group_routes = [route]
            continue

        # after the loop, need to pack the last tmp group
        if tmp_group_key and tmp_group_routes:
            groups[f'{len(groups)}_{route_group_key}'] = tmp_group_routes

        if not default_rule:
            raise Exception(f'default action for routing filter {name} is missing')

        _, default_rule_action, default_rule_next_hop, default_rule_custom = default_rule

        route_map_seq = 5  # each route-map should have different order number.
        for idx, group_key in enumerate(groups):
            routes = groups[group_key]
            _, action, next_hop, custom = group_key.split('_')

            access_list_name = f'rm_{name}_group_{idx}'
            for route in routes:
                add_commands.append(f'ip prefix-list {access_list_name} permit {route}')
            remove_commands.append(f'no ip prefix-list {access_list_name}')

            if custom:
                custom = ast.literal_eval(custom) # convert string to list
            add_commands += self.translate_route_map_to_frr_commands(name, description, action, route_map_seq, access_list_name, next_hop, custom)
            route_map_seq += 5

        # add default rule route map at the end
        add_commands += self.translate_route_map_to_frr_commands(name, description, default_rule_action, route_map_seq, None, default_rule_next_hop, default_rule_custom)
        remove_commands.append(f'no route-map {name}')

        return add_commands, remove_commands

    def get_bgp_summary_json(self):
        try:
            if not fwglobals.g.router_api.state_is_started():
                return {}

            if not fwglobals.g.router_cfg.get_bgp():
                return {}

            cmd = 'vtysh -c "show bgp summary json"'
            frr_json_output = subprocess.check_output(cmd, shell=True).decode().strip()
            # {
            #   "ipv4Unicast":{
            #     "routerId":"192.168.1.108",
            #     "as":1234,
            #     "vrfId":0,
            #     "vrfName":"default",
            #     "tableVersion":1,
            #     "ribCount":1,
            #     "ribMemory":192,
            #     "peerCount":1,
            #     "peerMemory":741464,
            #     "peers":{
            #       "7.7.7.7":{
            #         "remoteAs":77,
            #         "localAs":1234,
            #         "version":4,
            #         "msgRcvd":0,
            #         "msgSent":0,
            #         "tableVersion":0,
            #         "outq":0,
            #         "inq":0,
            #         "peerUptime":"never",
            #         "peerUptimeMsec":0,
            #         "pfxRcd":0,
            #         "pfxSnt":0,
            #         "state":"Idle",
            #         "peerState":"OK",
            #         "connectionsEstablished":0,
            #         "connectionsDropped":0,
            #         "idType":"ipv4"
            #       }
            #     },
            #     "failedPeers":1,
            #     "displayedPeers":1,
            #     "totalPeers":1,
            #     "dynamicPeers":0,
            #     "bestPath":{
            #       "multiPathRelax":"true"
            #     }
            #   }
            # }
            output_json = json.loads(frr_json_output).get('ipv4Unicast', {})
            if not output_json:
                return {}

            res = {
                'routerId': output_json.get('routerId'),
                'as': output_json.get('as'),
                'failedPeers': output_json.get('failedPeers'),
                'displayedPeers': output_json.get('displayedPeers'),
                'totalPeers': output_json.get('totalPeers'),
                'peers': {}
            }

            peers = output_json.get('peers', [])
            for peer_ip in peers:
                res['peers'][peer_ip] = {
                    'remoteAs': peers[peer_ip]['remoteAs'],
                    'msgRcvd': peers[peer_ip]['msgRcvd'],
                    'msgSent': peers[peer_ip]['msgSent'],
                    'peerUptime': peers[peer_ip]['peerUptime'],
                    'peerUptimeMsec': peers[peer_ip]['peerUptimeMsec'],
                    'pfxRcd': peers[peer_ip]['pfxRcd'],
                    'pfxSnt': peers[peer_ip]['pfxSnt'],
                    'state': peers[peer_ip]['state'],
                    'peerState': peers[peer_ip]['peerState']
                }

            return res
        except Exception as e:
            self.log.error(f"get_bgp_summary_json(): {str(e)}")
            raise e

    def get_routes_json(self, address, dev=None, ignore_default_routes=True):
        '''Fetches routes to provided destination address from FRR.
        FRR keeps all available routes, including not optimal ones.

        :param address: either prefix or destination IP for which routes should be retrieved
        :param dev:     name of device, route through should be retrieved
        :param ignore_default_routes: if True, default routes will be not fetched

        :return: dictionary where key is destination address, and value is a list of available routes
        '''
        try:
            cmd = ['vtysh', '-c', f'show ip route {address} json']
            frr_json_output = subprocess.check_output(cmd).decode().strip()
            output_json     = json.loads(frr_json_output)
            if not dev:
                return output_json

            # vtysh -c "show ip route 10.77.77.10 json"
            # {
            #   "10.77.77.0/24":[
            #     {
            #       "prefix":"10.77.77.0/24",
            #       "prefixLen":24,
            #       "protocol":"ospf",
            #       "vrfId":0,
            #       "vrfName":"default",
            #       "distance":110,
            #       "metric":10000,
            #       "table":254,
            #       "internalStatus":0,
            #       "internalFlags":0,
            #       "internalNextHopNum":1,
            #       "internalNextHopActiveNum":1,
            #       "nexthopGroupId":98,
            #       "uptime":"00:54:18",
            #       "nexthops":[
            #         {
            #           "flags":1,
            #           "directlyConnected":true,
            #           "interfaceIndex":11,
            #           "interfaceName":"vpp2.1",
            #           "active":true,
            #           "weight":1
            #         }
            #       ]
            #     },
            #     {
            #       "prefix":"10.77.77.0/24",
            #       "prefixLen":24,
            #       "protocol":"connected",
            #       "vrfId":0,
            #       "vrfName":"default",
            #       "selected":true,
            #       "destSelected":true,
            #       "distance":0,
            #       "metric":0,
            #       "installed":true,
            #       "table":254,
            #       "internalStatus":16,
            #       "internalFlags":8,
            #       "internalNextHopNum":1,
            #       "internalNextHopActiveNum":1,
            #       "nexthopGroupId":84,
            #       "installedNexthopGroupId":84,
            #       "uptime":"00:54:19",
            #       "nexthops":[
            #         {
            #           "flags":3,
            #           "fib":true,
            #           "directlyConnected":true,
            #           "interfaceIndex":11,
            #           "interfaceName":"vpp2.1",
            #           "active":true
            #         }
            #       ]
            #     }
            #   ]
            # }
            output = {}
            for addr, routes in output_json.items():
                found_routes = []
                for route in routes:
                    if ignore_default_routes and route['prefix'] == "0.0.0.0/0":
                        continue
                    found_nexthops = []
                    for nexthop in route.get('nexthops',[]):
                        if nexthop['active'] and nexthop.get('interfaceName') == dev:
                            found_nexthops.append(nexthop)
                    if found_nexthops:
                        route.update({'nexthops': found_nexthops})
                        found_routes.append(route)
                if found_routes:
                    output.update({addr: found_routes})
            return output
        except Exception as e:
            self.log.error(f"get_routes_json(): {str(e)}")
            raise e

    def get_bgp_neighbors_json(self):
        cmd = 'vtysh -c "show bgp neighbors json"'
        frr_json_output = subprocess.check_output(cmd, shell=True).decode().strip()
        return json.loads(frr_json_output)

    def get_ospf_interfaces_json(self):
        cmd = 'vtysh -c "show ip ospf interface json"'
        frr_json_output = subprocess.check_output(cmd, shell=True).decode().strip()
        return json.loads(frr_json_output)

    def is_ospf_passive_mode_enabled(self):
        ospf_interfaces = self.get_ospf_interfaces_json().get('interfaces', {})
        if not ospf_interfaces:
            return None
        # As we use global 'passive-interface' flag, it should appear in all interfaces.
        # Therefore it is enough to check one interface only.
        return 'timerPassiveIface' in list(ospf_interfaces.values())[0]

    def get_ospf_route_map_tags(self):
        # currently we use two route-maps for redistribution routes: kernel and static
        res = {}

        def _get_route_map_tag(route_map):
            rules = route_map.get('rules', [])
            if rules:
                set_actions = rules[0].get('setClauses', [])
                for set_action in set_actions:
                    if 'tag' in set_action:
                        return set_action.split(' ')[-1]
            return None

        # The output from "vtysh" in this case returns invalid JSON without a comma between the sections.
        # Using "jq -c" (where -c stands for "compact") is helpful as it allows us
        # to use "splitlines" to return each section in a separate line.
        # This makes it possible to use "json.loads()" on it.
        #
        cmd = 'vtysh -c "show route-map json" | jq -c'
        frr_protocols = subprocess.check_output(cmd, shell=True).decode().splitlines()
        # {"ZEBRA":{"fw-redist-bgp-rm":{"invoked":0,"disabledOptimization":false,"processedChange":false,"rule...
        # {"OSPF":{"fw-redist-bgp-rm":{"invoked":0,"disabledOptimization":false,"processedChange":false,"rules...
        # {"BGP":{"fw-redist-bgp-rm":{"invoked":2,"disabledOptimization":false,"processedChange":false,"rules"...

        for frr_protocol in frr_protocols:
            protocol_route_maps = json.loads(frr_protocol)
            ospf_route_maps = protocol_route_maps.get('OSPF')
            if not ospf_route_maps:
                continue

            kernel_route_map = ospf_route_maps.get(fwglobals.g.FRR_OSPF_ROUTE_MAP)
            static_route_map = ospf_route_maps.get(fwglobals.g.FRR_LAN_NAT_ROUTE_MAP)

            if kernel_route_map:
                kernel_tag = _get_route_map_tag(kernel_route_map)
                res[fwglobals.g.FRR_OSPF_ROUTE_MAP] = { 'tag': kernel_tag, 'route_map': kernel_route_map }

            if static_route_map:
                static_tag = _get_route_map_tag(static_route_map)
                res[fwglobals.g.FRR_LAN_NAT_ROUTE_MAP] = { 'tag': static_tag, 'route_map': static_route_map }

        return res

    def validate_config(self, commands):
        # Use private temporary file instead of fixed /tmp path, as the commands
        # might include secrets, like BGP passwords (mkstemp creates 0600 file).
        fd, tmp_file = tempfile.mkstemp(prefix='frr.', suffix='.tmp')
        with os.fdopen(fd, 'w+') as f:
            f.write('\n'.join(commands))

        try:
            subprocess.check_output(['vtysh', '-f', tmp_file, '-C'],  stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            err = str(e.output.decode().strip())
            self.log.error(f"_validate_config({commands}) failed: {err}")
            raise Exception(err)
        except Exception as e:
            self.log.error(f"_validate_config({commands}) failed: {str(e)}")
            raise e
        finally:
            os.remove(tmp_file)
