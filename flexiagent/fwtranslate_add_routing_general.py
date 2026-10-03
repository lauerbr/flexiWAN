#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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

# {
#   "entity":"agent"
#   "message":"add-routing-general"
#   "params":{
#       "custom": []
#   }
# }
def add_routing_general(params):
    """Generate commands to add Routing general.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """

    cmd_list = []

    # "custom" includes a list of commands for FRR CLI (vtysh) to be executed on the root
    custom_commands = params.get('custom', [])
    if custom_commands:
        frr_commands = []
        remove_commands = []
        for custom_command in custom_commands:
            frr_commands.append(custom_command)
            remove_commands.append(f'no {custom_command}')

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "validate_config"
        cmd['cmd']['object']  = "fwglobals.g.router_api.frr"
        cmd['cmd']['descr']   =  "validate user FRR config"
        cmd['cmd']['params']  = { 'commands': frr_commands }
        cmd_list.append(cmd)

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']   = "frr_vtysh_run"
        cmd['cmd']['module'] = "fwutils"
        cmd['cmd']['descr']  =  "add global routing commands"
        cmd['cmd']['params'] = {
                    'commands'   : frr_commands,
                    'restart_frr': True,
                    'on_error_commands': remove_commands,
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "frr_vtysh_run"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['params'] = {
                    'commands'   : remove_commands,
                    'restart_frr': True,
                    'forgive_errors': True,
        }
        cmd['revert']['descr']   =  "remove global routing commands"
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Get add-routing-general key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-routing-general request.
    """
    key = 'add-routing-general' # only one request.
    return key
