#! /usr/bin/python3

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
import os
import sys
system_checker_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tools/system_checker/")
sys.path.append(system_checker_path)
import fwsystem_checker_common

# {
#   "entity": "agent",
#   "message": "set-cpu-info",
#   "params": {
#     "hwCores": 4,
#     "grubCores": 4,
#     "vppCores": 2,
#     "powerSaving": False
#   }
# }

def add_cpu_info(params):
    """Generate commands to add CPU Info configuration.

    :param params:        Parameters from flexiManage.

    :returns: cmd_list. List of commands.
    """
    cmd_list = []

    with fwsystem_checker_common.Checker() as checker:
        cpu_info = checker.get_cpu_info()

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']    = "set_cpu_info"
    cmd['cmd']['module']  = "fwutils"
    cmd['cmd']['descr']   =  "set cpu info settings"
    cmd['cmd']['params'] = {
                    'vpp_cores': params.get('vppCores'),
                    'power_saving': params.get('powerSaving'),
    }
    cmd['revert'] = {}
    cmd['revert']['func']   = "set_cpu_info"
    cmd['revert']['module'] = "fwutils"
    cmd['revert']['params'] = {
                    'vpp_cores': cpu_info.get('vppCores'),
                    'power_saving': cpu_info.get('powerSaving'),
    }
    cmd['revert']['descr']   =  f"revert cpu info settings"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-cpu-info key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-cpu-info request.
    """
    return 'set-cpu-info'
