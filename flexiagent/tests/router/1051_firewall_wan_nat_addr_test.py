'''
Firewall WAN NAT Address poll test cases execution - Picked by pytest
'''
################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2024  flexiWAN Ltd.
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

import glob
import os
import sys
import json
from vpp_api import VPP_API
import ipaddress

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
sys.path.append(code_root)
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests
import fwutils
import fwglobals


def check_01_nat_pool(test_file):
    """
    Function to validate if NAT address pool is configured correctly

    :param test_file: The name of the test file that represents this test case
    :type test_file: String
    :return: Return True if the test file configured VPP in the expected way
    :rtype: Boolean
    """
    nat_pool_addresses = []
    with open(test_file, 'r') as in_file:
        test_dict = json.load(in_file)
        for message in test_dict:
           if message['message'] == 'start-router':
                for interface in message['params']['interfaces']:
                    if interface['type'] == 'wan':
                        ip4_subnets = interface.get('wanNatAddresses')
                        if not ip4_subnets:
                            continue
                        for ip4_subnet in ip4_subnets:
                            continue
                        ip_context = ipaddress.ip_network(ip4_subnet)
                        for ip in list(ip_context.hosts()):
                            nat_pool_addresses.append(str(ip))
    vpp_api = VPP_API()
    vpp_out = vpp_api.vpp.call('nat44_address_dump')
    vpp_nat_addresses = []
    for out in vpp_out:
        ip_address = out.ip_address
        vpp_nat_addresses.append(str(ip_address))
    vpp_api.disconnect_from_vpp()
    for address in nat_pool_addresses:
        if not address in vpp_nat_addresses:
            return False
    return True


def check_02_nat_pool_inbound_edge_access(test_file):
    """
    Function to validate if Edge Access rule is configured correctly

    :param test_file: The name of the test file that represents this test case
    :type test_file: String
    :return: Return True if the test file configured VPP in the expected way
    :rtype: Boolean
    """
    nat_identity_mappings = []
    with open(test_file, 'r') as in_file:
        test_dict = json.load(in_file)
        for message in test_dict:
           if message['message'] == 'add-firewall-policy':
                for rule in message['params']['inbound']['edgeAccess']['rules']:
                    ip_address = rule['classification']['destination']['ip4Address']
                    protocols = rule['classification']['destination']['protocols']
                    ports = rule['classification']['destination']['ports']
                    for protocol in protocols:
                        port_from, port_to = fwutils.ports_str_to_range(ports)
                        for port in range(port_from, (port_to + 1)):
                            key = ip_address + ' ' + \
                                    str(fwutils.proto_map[protocol]) + ' ' +\
                                    str(port)
                            nat_identity_mappings.append(key)
    vpp_api = VPP_API()
    vpp_out = vpp_api.vpp.call('nat44_identity_mapping_dump')
    vpp_identity_mappings = set()
    for out in vpp_out:
        key = str(out.ip_address) + ' ' + \
                str(out.protocol) + ' ' +\
                str(out.port)
        vpp_identity_mappings.add(key)
    vpp_api.disconnect_from_vpp()
    for entry in nat_identity_mappings:
        if not entry in vpp_identity_mappings:
            return False
    return True


def check_03_nat_pool_inbound_nat_1to1(test_file):
    """
    Function to validate if inbound 1:1 NAT rule is configured correctly

    :param test_file: The name of the test file that represents this test case
    :type test_file: String
    :return: Return True if the test file configured VPP in the expected way
    :rtype: Boolean
    """
    nat_static_mappings = []
    with open(test_file, 'r') as in_file:
        test_dict = json.load(in_file)
        for message in test_dict:
           if message['message'] == 'add-firewall-policy':
                for rule in message['params']['inbound']['nat1to1']['rules']:
                    external_ip_address = rule['classification']['destination']['ip4Address']
                    local_ip_address = rule['action']['internalIP']
                    key = external_ip_address + ' ' + local_ip_address
                    nat_static_mappings.append(key)

    vpp_api = VPP_API()
    vpp_out = vpp_api.vpp.call('nat44_static_mapping_dump')
    vpp_static_mappings = set()
    for out in vpp_out:
        if (out.flags & 0x8): #ADDR_ONLY
            key = str(out.external_ip_address) + ' ' + str(out.local_ip_address)
            vpp_static_mappings.add(key)
    vpp_api.disconnect_from_vpp()
    for key in nat_static_mappings:
        if not (key in vpp_static_mappings):
            return False
    return True

def check_04_nat_pool_inbound_port_forward(test_file):
    """
    Function to validate if inbound port forward NAT rule is configured correctly

    :param test_file: The name of the test file that represents this test case
    :type test_file: String
    :return: Return True if the test file configured VPP in the expected way
    :rtype: Boolean
    """
    nat_static_mappings = []
    with open(test_file, 'r') as in_file:
        test_dict = json.load(in_file)
        for message in test_dict:
           if message['message'] == 'add-firewall-policy':
                for rule in message['params']['inbound']['portForward']['rules']:
                    external_ip_address = rule['classification']['destination']['ip4Address']
                    protocols = rule['classification']['destination']['protocols']
                    ports = rule['classification']['destination']['ports']
                    local_ip_address = rule['action']['internalIP']
                    for protocol in protocols:
                        local_port = rule['action']['internalPortStart']
                        port_from, port_to = fwutils.ports_str_to_range(ports)
                        for external_port in range(port_from, (port_to + 1)):
                            key = external_ip_address + ' ' +\
                                    str(fwutils.proto_map[protocol]) + ' ' +\
                                    str(external_port) + ' ' +\
                                    local_ip_address + ' ' +\
                                    str(local_port)
                            local_port += 1
                            nat_static_mappings.append(key)

    vpp_api = VPP_API()
    vpp_out = vpp_api.vpp.call('nat44_static_mapping_dump')
    vpp_static_mappings = set()
    for out in vpp_out:
        key = str(out.external_ip_address) + ' ' +\
                str(out.protocol) + ' ' +\
                str(out.external_port) + ' ' +\
                str(out.local_ip_address) + ' ' +\
                str(out.local_port)
        vpp_static_mappings.add(key)
    vpp_api.disconnect_from_vpp()
    for key in nat_static_mappings:
        if not (key in vpp_static_mappings):
            return False
    return True

def check_05_nat_pool_removal(test_file):
    """
    Function to validate if NAT addresses are removed correctly

    :param test_file: The name of the test file that represents this test case
    :type test_file: String
    :return: Return True if the test file configured VPP in the expected way
    :rtype: Boolean
    """
    vpp_api = VPP_API()
    vpp_out = vpp_api.vpp.call('nat44_address_dump')
    vpp_api.disconnect_from_vpp()
    # One address corresponds to interface WAN address.
    # If there are more entries then it indicates that the addresses are not removed
    if len(vpp_out) > 1:
        return False
    return True


def check_wan_nat_rules_removal():
    vpp_api = VPP_API()
    static_mappings_vpp_out = vpp_api.vpp.call('nat44_static_mapping_dump')
    identity_mappings_vpp_out = vpp_api.vpp.call('nat44_identity_mapping_dump')
    entries_removed = True
    if len(static_mappings_vpp_out):
        entries_removed = False
    elif len(identity_mappings_vpp_out):
        entries_removed = False
    vpp_api.disconnect_from_vpp()
    return entries_removed


def test():
    """
    Test function that gets called by pytest framework
    """
    fwglobals.initialize()
    tests_path = __file__.replace('.py', '')
    test_cases = sorted(glob.glob('%s/*.json' % tests_path))
    with fwtests.TestFwagent() as agent:
        for test_file in test_cases:
            print("   " + os.path.basename(test_file))
            (return_ok,_) = agent.cli('-f %s' % test_file)
            assert return_ok, "%s failed" % test_file

            api_name = 'check_' + os.path.basename(test_file).replace('.json', '')
            module_name = sys.modules[__name__]
            try:
                api_func = getattr(module_name, api_name)
                if api_func:
                    return_ok = api_func(test_file)
                    assert return_ok, "%s config check failed" % test_file
            except:
                raise

            cli_path = __file__.replace('.py', '')
            cli_remove_firewall_policy_file = os.path.join(cli_path, 'remove_firewall_policy.cli')
            (return_ok,_) = agent.cli('-f %s' % cli_remove_firewall_policy_file)
            assert return_ok, "%s remove_firewall_policy failed"
            return_ok = check_wan_nat_rules_removal()
            assert return_ok, "%s stale wan inbound nat entries exist"
            cli_stop_router_file = os.path.join(cli_path, 'stop_router.cli')
            (return_ok,_) = agent.cli('-f %s' % cli_stop_router_file)
            assert return_ok, "%s stop_router failed"
    fwglobals.finalize()


if __name__ == '__main__':

    test()
