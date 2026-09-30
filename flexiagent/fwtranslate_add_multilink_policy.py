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

import copy

import fwglobals
import fw_acl_command_helpers

# add-multilink-policy
# --------------------------------------
# Translates request:
#
# {
#    "entity": "agent",
#    "message": "add-multilink-policy",
#    "params": {
#        "id": "5e8d7d5305369313f5ceff5b",
#        "rules": [
#            {
#                "action": {
#                    "fallback": "by-destination",
#                    "links": [
#                        {
#                            "order": "priority",
#                            "pathlabels": [
#                                "5e8d7cc005369313f5ceff16"
#                            ]
#                        }
#                    ],
#                    "order": "priority"
#                },
#                "classification": {
#                    "application": {
#                        "category": "office",
#                        "importance": "",
#                        "name": "",
#                        "serviceClass": ""
#                    },
#                    "prefix": {}
#                },
#                "id": "5e8d7d5305369313f5ceff5c",
#                "priority": 0
#            },
#            {
#                "id": "2",
#                "priority": 0,
#                "classification": {
#                "prefix": {
#                    "ip": "8.8.8.8/32",
#                    "ports": "",
#                    "protocol": ""
#                }
#                },
#                "action": {
#                "links": [
#                    {
#                    "pathlabels": [ "green" , "blue" ],
#                    "order": "load-balance"
#                    },
#                    {
#                    "pathlabels": [ "blue" ],
#                    "order": "priority"
#                    }
#                ],
#                "order": "load-balance",
#                "fallback": "by-destination"
#                }
#            },
#            ...
#        ]
#    }
# }

policy_index = 0

def _generate_id(ret):
    """Generate identifier.

    :param ret:         Initial id value.

    :returns: identifier.
    """
    ret += 1
    if ret == 2 ** 32:  # sad_id is u32 in VPP
        ret = 0
    return ret

def _generate_policy_id():
    """Generate policy identifier.

    :returns: New policy identifier.
    """
    global policy_index
    policy_index = _generate_id(policy_index)
    return copy.deepcopy(policy_index)

def reset_policy_id():
    """Reset policy identifier.
    """
    global policy_index
    policy_index = 0


def add_multilink_policy(params):
    """Translates the received from flexiManage 'add-multilink-policy' request
    into list of commands to be executed in order to configure policy in VPP.

    :param params: the 'params' section of the 'add-multilink-policy' request.

    :returns: List of commands.
    """
    cmd_list = []
    cache_key = 'multilink-acl-index'

    # Every rule in the received 'add-multilink-policy' request creates Policy object in VPP

    for rule in params['rules']:

        # Build translation that creates ACL object in VPP.
        # The ACL might have a list of matching rules. The matching rules are
        # generated out of the policy 'classification' parameter.
        # The classification can include either ID of specific application ('appId')
        # or an implicit set of applications marked by category/serviceClass/importance.
        # Note even if specific application was provided by the classification,
        # we still might generate a list of matching rules, as application might
        # have multiple matching rules. The application matching rules are called
        # traffic identification rules. So we gather traffic identification rules
        # for all applications classified by this policy, than we convert these
        # rules into list of ACL matching rules that later will be feed into the
        # single ACL object that will serve the policy.
        #
        destination        = {}
        traffic_class      = None
        traffic_importance = None
        app_id             = None

        prefix = rule['classification'].get('prefix')
        if prefix:
            destination['ipProtoPort'] = prefix
            traffic_class              = 'default'
            traffic_importance         = 'low'
        else:
            app = rule['classification']['application']
            traffic_id         = app.get('appId')
            traffic_category   = app.get('category')
            traffic_class      = app.get('serviceClass')
            traffic_importance = app.get('importance')

            if traffic_id:# application based
                destination['trafficId'] = traffic_id
                traffic_category, traffic_class, traffic_importance = fwglobals.g.traffic_identifications.get_app_attributes(traffic_id)
                app_id = traffic_id
            else:  # tag based
                destination['trafficTags'] = {
                    'category': traffic_category,
                    'service_class': traffic_class,
                    'importance': traffic_importance
                }

        acl_user_attr = fw_acl_command_helpers.build_acl_user_attributes(None, traffic_class, traffic_importance)
        cmd_list.extend(fw_acl_command_helpers.generate_add_acl_rule_commands(
            acl_id=cache_key,
            source=None,
            destination=destination,
            permit=True,
            is_ingress=None, # None = both sides
            acl_user_attr=acl_user_attr,
            app_id=app_id
        ))

        # Now build translation that creates Policy object in VPP.
        #
        rule_id   = rule['id']
        priority  = rule['priority']
        fallback  = rule['action'].get('fallback', 'by-destination')
        order     = rule['action'].get('order', 'priority')
        links     = rule['action']['links']
        override_default_route = rule.get('override-default-route', False)
        attach_to_wan        = rule.get('apply-on-wan-rx', False)
        policy_id = _generate_policy_id()

        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['func']    = "vpp_multilink_update_policy_rule"
        cmd['cmd']['module']  = "fwutils"
        cmd['cmd']['descr']   = f"add policy (id={policy_id}, {rule['id']})"
        cmd['cmd']['params']  = {
                        'add': True, 'links': links, 'policy_id': policy_id,
                        'fallback': fallback, 'order': order, 'priority': priority,
                        'override_default_route': override_default_route,
                        'attach_to_wan': attach_to_wan, 'rule_id': rule_id,
                        'substs' : [{'add_param': 'acl_index', 'val_by_key': cache_key}]
        }
        cmd['revert'] = {}
        cmd['revert']['func']   = "vpp_multilink_update_policy_rule"
        cmd['revert']['module'] = "fwutils"
        cmd['revert']['descr']  = f"remove policy (id={policy_id}, {rule['id']})"
        cmd['revert']['params'] = {
                        'add': False, 'links': links, 'policy_id': policy_id,
                        'fallback': fallback, 'order': order, 'priority': priority,
                        'override_default_route': override_default_route,
                        'attach_to_wan': attach_to_wan, 'rule_id': rule_id,
                        'substs' : [{'add_param': 'acl_index', 'val_by_key': cache_key}]
        }
        cmd_list.append(cmd)

    return cmd_list

def get_request_key(params):
    """Return policy key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'add-multilink-policy'
