#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2025  flexiWAN Ltd.
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

import os
import sys
agent_root_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..')
sys.path.append(agent_root_dir)

import fwnetplan

def argparse(configure_subparsers):

    # Following are examples of the supported commands:
    # >> fwagent configure agent connection recovery stop

    configure_agent_parser = configure_subparsers.add_parser('agent', help='Configure agent commands')
    configure_agent_subparsers = configure_agent_parser.add_subparsers(dest='agent', required=True)

    connection_parser = configure_agent_subparsers.add_parser('connection', help='Connection option')
    connection_subparsers = connection_parser.add_subparsers(dest='connection', required=True)

    recovery_parser = connection_subparsers.add_parser('recovery', help='Recovery option')
    recovery_subparsers = recovery_parser.add_subparsers(dest='recovery', required=True)
    recovery_subparsers.add_parser('stop', help='Stop connection recovery')

def connection_recovery_stop():
    fwnetplan.stop_recovery_netplan()
