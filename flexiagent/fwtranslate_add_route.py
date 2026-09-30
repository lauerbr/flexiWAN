#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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

# add_route
# --------------------------------------
# Translates request:
#
#    {
#       "message": "add-route",
#       "params": {
#           "addr":"10.0.0.4/24" (OR "10.0.0.4" OR "default")
#           "via":"192.168.1.1",
#           "dev_id":"0000:00:08.00",   (device, optional)
#           "destinationType": "", (OR "fqdn")
#       }
#    }
#
# into one of following commands:
#
#   ip route add default via 192.168.1.1 [dev <interface>]
#   ip route add 192.0.2.1 via 10.0.0.1 [dev <interface>]
#   ip route add 192.0.2.0/24 via 10.0.0.1 [dev <interface>]
#
#   On CentOS/Fedora/RH "systemctl restart network.service" is needed afterwards.
#
#
def add_route(params):
    """Generate commands to configure ip route in Linux and VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    addr      = params.get('addr')
    via       = params.get('via')
    dev_id    = params.get('dev_id')
    dest_type = params.get('destinationType')

    if dest_type == 'fqdn':
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "set"
        cmd['cmd']['object']    = "fwglobals.g.fqdn_resolver"
        cmd['cmd']['descr']     = f"add {addr} to the FQDN resolver thread"
        cmd['cmd']['params']    = {
            'fqdn'  : addr,
            'func_module': 'fwroutes',
            'func_name'  : 'handle_fqdn_static_routes',
            'func_params': { 'params': params }
        }
        cmd['cmd']['cache_ret_val'] = ('callback_id', 'callback_id')
        cmd['revert'] = {}
        cmd['revert']['func']   = "unset"
        cmd['revert']['object'] = "fwglobals.g.fqdn_resolver"
        cmd['revert']['descr']  = f"remove {addr} from the FQDN resolver thread"
        cmd['revert']['params'] = {
            'fqdn'  : addr,
            'substs': [ { 'add_param':'callback_id', 'val_by_key':'callback_id'} ]
        }
        cmd_list.append(cmd)
    else:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "install_uninstall_route"
        cmd['cmd']['module']    = "fwroutes"
        cmd['cmd']['descr']     = f"Install route add {addr} via {via} dev {dev_id}"
        cmd['cmd']['params']    = { 'is_add': True, 'params': params }
        cmd['revert'] = {}
        cmd['revert']['func']   = "install_uninstall_route"
        cmd['revert']['module'] = "fwroutes"
        cmd['revert']['descr']  = f"Uninstall route add {addr} via {via} dev {dev_id}"
        cmd['revert']['params'] = { 'is_add': False, 'params': params }
        cmd_list.append(cmd)
    return cmd_list

def get_request_key(params):
    """Get add route command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    if 'dev_id' in params:
        key = 'add-route:%s:%s:%s' % (params['addr'], params['via'], params['dev_id'])
    elif 'pci' in params: # Used for pci_to_dev_id migration only to compute the right key
        key = 'add-route:%s:%s:%s' % (params['addr'], params['via'], params['pci'])
    else:
        key = 'add-route:%s:%s' % (params['addr'], params['via'])

    if params.get('metric'):
        key += ':' + str(params['metric'])

    return key
