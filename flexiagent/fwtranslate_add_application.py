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

from fw_traffic_identification import APP_CLASSIFICATION_ACLS_LIST_ID
import fwglobals
import fw_acl_command_helpers


# add-application
# --------------------------------------
# Translates request:
# {
#   "entity":  "agent",
#   "message": "add-application",
#   "params": [{
#            "app":"google-dns",
#            "id":1,
#            "category":"network",
#            "serviceClass":"dns",
#            "priority":3,
#            "rules":[
#                {
#                   "ip":"8.8.8.8/32",
#                   "ports":"53"
#               },
#               {
#                   "ip":"8.8.4.4/32",
#                   "ports":"53"
#               },
#               {
#                   "fqdn": "domain.com",
#                   "ports": []
#               }
#           ]
#       }]
# }

def _add_traffic_identification(params, cmd_list):
    """
    Add traffic/application identification to the internal sqldict context

    :param params: add-application message from carrying the traffic/app match definitions
    :type params: dict
    :param cmd_list: Command array to be updated with corresponding commands
    :type cmd_list: Array
    """
    cmd = {}

    rules = [r for r in params['rules'] if 'fqdn' not in r]  # Exclude FQDN rules; they will be updated in the database upon resolution.

    cmd['cmd'] = {}
    cmd['cmd']['func']   = "add_traffic_identification"
    cmd['cmd']['object'] = "fwglobals.g.traffic_identifications"
    cmd['cmd']['descr']  = f"Add Traffic Identification {params['id']}"
    cmd['cmd']['params'] = { 'traffic': { **params, 'rules': rules }}

    cmd['revert'] = {}
    cmd['revert']['func']   = "remove_traffic_identification"
    cmd['revert']['object'] = "fwglobals.g.traffic_identifications"
    cmd['revert']['descr']  = f"Delete Traffic Identification {params['id']}"
    cmd['revert']['params'] = { 'traffic': { **params, 'rules': rules }}
    cmd_list.append(cmd)


def _add_traffic_identification_acl(app, acl_key_list, cmd_list):
    """
    Generate commands to match Application / Traffic Identification as ACLs
    The match definition ACLs are programmed with the configured service-class and
    importance attributes

    :param app: Application object
    :type traffic: dict
    :param acl_key_list: An array to store the key of the generated ACL
    :type acl_key_list: Array
    :param cmd_list: Array to store the generated configuration commands
    :type cmd_list: Array
    """
    service_class = app.get('serviceClass', 'default')
    importance    = app.get('importance', 'low')
    traffic_id    = app.get("id")

    acl_user_attr = fw_acl_command_helpers.build_acl_user_attributes(None, service_class, importance)

    static_ips  = []
    fqdns       = []

    for rule in app['rules']:
        if 'fqdn' in rule:
            fqdns.append(rule)
        else:
            static_ips.append(rule)

    destination = {}

    if static_ips:
        destination['ipProtoPort'] = static_ips

    if fqdns:
        # FQDN rules are unresolved at this point.
        # Add the "trafficId" to the "Destination" to signal the next function ("_generate_acl_rules_vpp_params")
        # to include IPs from the DB, in addition to the static IPs provided.
        destination['trafficId'] = traffic_id

    acl_id_1 = f'fw_app_rule_{traffic_id}'
    acl_id_2 = f'fw_app_rule_{traffic_id}_reverse'

    commands1 = fw_acl_command_helpers.generate_add_acl_rule_commands(
        acl_id=acl_id_1,
        source=None,
        destination=destination,
        permit=True,
        is_ingress=False,
        acl_user_attr=acl_user_attr,
        app_id=traffic_id
    )

    commands2 = fw_acl_command_helpers.generate_add_acl_rule_commands(
        acl_id=acl_id_2,
        source=None,
        destination=destination,
        permit=True,
        is_ingress=True,
        acl_user_attr=acl_user_attr,
        app_id=traffic_id
    )

    if not commands1 or not commands2:
        fwglobals.log.error(f'Application ACLs : ACL generate failed - Index {traffic_id}')
        return

    cmd_list.extend(commands1)
    cmd_list.extend(commands2)
    acl_key_list.append(acl_id_1)
    acl_key_list.append(acl_id_2)

    for fqdn_rule in fqdns:
        ports     = fqdn_rule.get('ports')
        protocols = fqdn_rule.get('protocols')
        fqdn      = fqdn_rule.get('fqdn')

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']      = "set"
        cmd['cmd']['object']    = "fwglobals.g.fqdn_resolver"
        cmd['cmd']['descr']     = f"add {fqdn} to the FQDN resolver thread"
        cmd['cmd']['params']    = {
            'fqdn'  : fqdn,
            'func_module': 'fw_acl_command_helpers',
            'func_name'  : 'handle_app_fqdn_change',
            'func_params': {
                'traffic_id': traffic_id,
                'ports'     : ports,
                'protocols' : protocols,
            }
        }
        cmd['cmd']['cache_ret_val'] = ('callback_id', 'callback_id')
        cmd['revert'] = {}
        cmd['revert']['func']   = "unset"
        cmd['revert']['object'] = "fwglobals.g.fqdn_resolver"
        cmd['revert']['descr']  = f"remove {fqdn} from the FQDN resolver thread"
        cmd['revert']['params'] = {
            'fqdn'  : fqdn,
            'substs': [ { 'add_param':'callback_id', 'val_by_key':'callback_id'} ]
        }
        cmd_list.append(cmd)

def _get_classification_setup_command(app_acl_ids, cmd_list):
    """
    Generate commands to attach classification ACLs to the given interface

    :param app_acl_ids: It can either be an integer representing the ACL index or a key
    to be used to lookup the actual acl_index from the command cache
    :type app_acl_ids: Array
    :param cmd_list: Array of generated configuration commands
    :type cmd_list: Array
    """
    add_param_acl_ids = False if isinstance(app_acl_ids[0], int) else True

    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['func']  = "call_vpp_api"
    cmd['cmd']['descr'] = "Setup classification ACLs"
    cmd['cmd']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['cmd']['params'] = {
        'api':  "classifier_acls_set_acls",
        'args': {
            'count' : len(app_acl_ids),
            'acl_list_id': APP_CLASSIFICATION_ACLS_LIST_ID,
        }
    }
    args = cmd['cmd']['params']['args']
    if add_param_acl_ids:
        args['substs'] = [{
            'add_param':            'acls',
            'val_by_func':          'map_keys_to_acl_ids',
            'arg': {
                'keys': app_acl_ids,
                'cmd_cache': fwglobals.g.router_api.cmd_cache
            }
        }]
    else:
        args['acls'] = app_acl_ids

    cmd['revert'] = {}
    cmd['revert']['func']  = "call_vpp_api"
    cmd['revert']['descr'] = "Clear classification ACLs"
    cmd['revert']['object'] = "fwglobals.g.router_api.vpp_api"
    cmd['revert']['params'] = {
        'api': "classifier_acls_set_acls",
        'args': {
            'count': 0,
            'acl_list_id': APP_CLASSIFICATION_ACLS_LIST_ID,
            'acls': [],
        }
    }
    cmd_list.append(cmd)

def add_application(params):
    """Generate App commands.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
    """
    cmd_list = []
    acl_key_list = []

    for app in params['applications']:
        _add_traffic_identification(app, cmd_list)
        _add_traffic_identification_acl(app, acl_key_list, cmd_list)
    _get_classification_setup_command(acl_key_list, cmd_list)
    return cmd_list


def get_request_key(params):
    """Return app key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-application'
