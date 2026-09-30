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

# This script is called by OpenVpn on client connection
# In order to create a dynamic config file to be applied on the server when the client connects,
# it should write it to the file named by the last argument.

import json
import os
import sys
import traceback
from ipaddress import IPv4Network

import script_utils
from scripts_logger import Logger

logger = Logger()

conf_file = sys.argv[1]

def get_static_routes():
    static_routes = []
    try:
        output = os.popen('fwagent show --configuration router').read()
        if not output:
            return static_routes

        j = json.loads(output)
        for config_key, config_value in j.items():
            if not 'ROUTES' in config_key:
                continue

            for route in config_value:
                params = route.get('Params', {})
                if not params.get('redistributeViaOSPF') and not params.get('redistributeViaBGP'):
                    continue
                static_routes.append(params.get('addr'))
    except Exception as err:
        logger.error(f"client-connect get_static_routes() failed: {err}. {traceback.extract_stack()}")
    return static_routes

try:
    is_device_higher_than_5_3 = script_utils.is_device_higher_than(5, 3)

    # get all frr routes
    frr_output = os.popen('vtysh -c "show ip route json"').read()
    parsed = json.loads(frr_output)

    routes = set()

    # push ospf/bgp routes to the clients
    for network in parsed:
        for item in parsed[network]:
            protocol = item.get('protocol')
            if not (protocol == 'ospf' or protocol == 'bgp'):
                continue

            ip_network = IPv4Network(network)
            network = ip_network.network_address
            netmask = ip_network.netmask
            routes.add(f'push \"route {network} {netmask}\"')

    if is_device_higher_than_5_3:
        networks = []

        # this cli introduced from 5.3 version
        # [root@flexiwan-router /usr/bin]# fwagent show --configuration networks
        # [
        #   "185.55.66.1/24"
        # ]
        agent_networks = os.popen('fwagent show --networks lan').read()
        if agent_networks:
            networks += json.loads(agent_networks)

        networks += get_static_routes()

        for network in networks:
            ip_network = IPv4Network(network, False) # False to ignore host bits error. LAN IP is not the network but an host in the network.
            network = ip_network.network_address
            netmask = ip_network.netmask
            routes.add(f'push \"route {network} {netmask}\"')

    if len(routes) > 0:
        route_str = '\n'.join(routes)
        os.system(f"sudo echo '{route_str}' >> {conf_file}")

except Exception as e:
    logger.error(f"client-connect: {str(e)}. {str(traceback.extract_stack())}")
    # returning 1 as exit code will disconnect the client
    sys.exit(1)
