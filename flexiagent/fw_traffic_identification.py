"""
DB for traffic identification store and lookup
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

import fwglobals

from fwobject import FwObject

# Valid service class values are between 0 to 15 (4 bits, Values 13 to 15 are unused at this point)
MAX_TRAFFIC_SERVICE_CLASSES = 16

#Update the below variable on adding new service class
HIGHEST_IN_USE_TRAFFIC_CLASS = 10

TRAFFIC_SERVICE_CLASS_VALUES = {
    'telephony'                 : 0,
    'broadcast-video'           : 1,
    'real-time'                 : 2,
    'signaling'                 : 3,
    'network-control'           : 4,
    'low-latency'               : 5,
    'oam'                       : 6,
    'high-throughput'           : 7,
    'multimedia-conferencing'   : 8,
    'multimedia-streaming'      : 9,
    'custom:new service class'  : 10,
    'default'                   : 10,
}

#Valid importance values are between 0 and 2 (2 bits, Value 3 is unused)
MAX_TRAFFIC_IMPORTANCE_VALUES = 4

TRAFFIC_IMPORTANCE_VALUES = {
    'low'                       : 0,
    'medium'                    : 1,
    'high'                      : 2
}

# Unique ID to represent the list of application ACLs in classifier plugin
APP_CLASSIFICATION_ACLS_LIST_ID = 0

class FwTrafficIdentifications(FwObject):

    """ Encapsulates functions associated with storing/removing/searching traffic identifiers.
    Each traffic identifier is a set of rules with match conditions and  carries traffic tags like
    category type, traffic class type and traffic importance
    """
    def __init__(self, db_file, logger=None):
        FwObject.__init__(self)

        self.traffic_id_map     = fwglobals.g.create_sqlite_dict(f"{db_file}.traffic_id_to_acl")
        self.category_map       = fwglobals.g.create_sqlite_dict(f"{db_file}.category_to_tid")
        self.traffic_class_map  = fwglobals.g.create_sqlite_dict(f"{db_file}.traffic_class_to_tid")
        self.importance_map     = fwglobals.g.create_sqlite_dict(f"{db_file}.importance_to_tid")
        if logger:
            self.log = logger   # override default logger created by FwObject.__init__() 

    def finalize(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def clean(self):
        """
        Removes all entries in the traffic identifier DBs
        """
        self.traffic_id_map.clear()
        self.category_map.clear()
        self.traffic_class_map.clear()
        self.importance_map.clear()

    def __add_traffic_id(self, dict_store, key, traffic_id):

        values = dict_store.get(key, set())
        values.add(traffic_id)
        dict_store[key] = values

    def __remove_traffic_id(self, dict_store, key, traffic_id):
        values = dict_store.get(key, None)
        if values:
            values.remove(traffic_id)
            dict_store[key] = values

    def reset_vpp_acl_indexes(self):
        for traffic_id in self.traffic_id_map:
            if 'vpp_acl_indexes' in self.traffic_id_map:
                self.traffic_id_map[traffic_id]['vpp_acl_indexes'] = []

    def get_traffic_vpp_acl_indexes(self, traffic_id):
        """
        Retrieves the VPP ACL indexes for a specific application.

        :param traffic_id: String representing the ID of the application whose ACL indexes are to be retrieved.
        :return: Dictionary with VPP ACL indexes as keys and their corresponding parameters as values.
        """
        if not traffic_id in self.traffic_id_map:
            return {}
        return self.traffic_id_map[traffic_id].get('vpp_acl_indexes', {})

    def add_remove_app_vpp_acl_index(self, is_add, traffic_id, acl_index, acl_parameters=None):
        """
        Updates the ACL index for a specific application.

        This method either adds or removes an ACL index associated with a traffic application,
        based on the `is_add` flag. If adding, it also updates the parameters associated with
        the ACL index.

        :param is_add: Boolean flag indicating whether to add or remove the `acl_index`.
        :param traffic_id: String representing the ID of the application to be updated.
        :param acl_index: String representing the ACL index to be added or removed.
        :param acl_parameters: Dictionary of parameters associated with the ACL.
        """
        if not traffic_id in self.traffic_id_map:
            return

        traffic = self.traffic_id_map[traffic_id]
        if 'vpp_acl_indexes' not in traffic:
            traffic['vpp_acl_indexes'] = {}

        if acl_index not in traffic['vpp_acl_indexes']:
            traffic['vpp_acl_indexes'][acl_index] = {}

        if is_add:
            traffic['vpp_acl_indexes'][acl_index].update(acl_parameters or {})
        else:
            del traffic['vpp_acl_indexes'][acl_index]

        # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        self.traffic_id_map[traffic_id] = traffic

    def update_traffic_identification_ips(self, traffic_id, ip_rules, old_ip_rules):
        """
        Updates the IP rules for a specific application.

        This method modifies the set of IP rules associated with a given traffic identifier.
        It removes the specified `old_ip_rules` and adds the new `ip_rules` on top of the
        existing ones.

        :param traffic_id: String identifier for the traffic to be updated.
        :param ip_rules: List of new IP rules to be added. These will be appended to the
                        existing rules, avoiding duplicates.
        :param old_ip_rules: List of IP rules to be removed from the existing set.
        """
        if not traffic_id in self.traffic_id_map:
            return

        traffic = self.traffic_id_map[traffic_id]
        updated = list(traffic['rules'])

        for ip_rule in old_ip_rules:
            if ip_rule in updated:
                updated.remove(ip_rule)
        for ip_rule in ip_rules:
            if ip_rule not in updated:
                updated.append(ip_rule)

        traffic['rules'] = updated
        # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        self.traffic_id_map[traffic_id] = traffic

    def get_app_attributes(self, traffic_id):
        """Looks up the traffic identification database and returns application attributes

        :param traffic_id: String identifier representing a traffic
        :return: Tuple of three items: category, service_class, importance
        """
        if not traffic_id in self.traffic_id_map:
            return None, None, None
        traffic = self.traffic_id_map[traffic_id]
        return traffic.get('category'), traffic.get('serviceClass'), traffic.get('importance')

    def add_traffic_identification(self, traffic):
        """ Adds traffic identification to the traffic identifier database

        :param traffic: json/dict message carrying the identification details
        """
        traffic_id = traffic.get("id")
        category = traffic.get("category")
        traffic_class = traffic.get("serviceClass")
        importance = traffic.get("importance")
        self.traffic_id_map[traffic_id] = traffic
        self.log.info('Add traffic identification: ' + traffic_id)
        if category:
            self.__add_traffic_id(self.category_map, category, traffic_id)
        if traffic_class:
            self.__add_traffic_id(self.traffic_class_map, traffic_class, traffic_id)
        if importance:
            self.__add_traffic_id(self.importance_map, importance, traffic_id)

    def remove_traffic_identification(self, traffic):
        """ Removes traffic identification to the traffic identifier database

        :param traffic: json/dict message carrying the identification details
        """
        traffic_id = traffic.get("id")
        category = traffic.get("category")
        traffic_class = traffic.get("serviceClass")
        importance = traffic.get("importance")
        self.log.info('Remove traffic identification: ' + traffic_id)
        if traffic_id in self.traffic_id_map:
            del self.traffic_id_map[traffic_id]
        if category:
            self.__remove_traffic_id(self.category_map, category, traffic_id)
        if traffic_class:
            self.__remove_traffic_id(self.traffic_class_map, traffic_class, traffic_id)
        if importance:
            self.__remove_traffic_id(self.importance_map, importance, traffic_id)

    def get_traffic_rules(self, traffic_id, category, traffic_class, importance):
        """Looks up the traffic identification database based on the passed
        match conditions and returns the result of traffic identifiers.
        The result is a intersection set of all match conditions

        :param traffic_id: String identifier representing a traffic
        :param category: String name representing the traffic category type
        :param traffic_class: String name representing the traffic class
        :param importance: String name representing the traffic importance
        :return: Array of dict and each dict carries the traffic match condition
        """
        traffic_id_set = set()
        rules = []
        if traffic_id:
            if traffic_id in self.traffic_id_map:
                traffic_id_set.add(traffic_id)
        else:
            traffic_ids = []
            if category and category in self.category_map:
                traffic_ids.append(self.category_map.get(category))

            if traffic_class and traffic_class in self.traffic_class_map:
                traffic_ids.append(self.traffic_class_map.get(traffic_class))

            if importance and importance in self.importance_map:
                traffic_ids.append(self.importance_map.get(importance))

            if traffic_ids:
                traffic_id_set = set.intersection(*traffic_ids)

        for traffic_id in traffic_id_set:
            traffic = self.traffic_id_map.get(traffic_id)
            traffic_rules = traffic.get('rules', [])
            for traffic_rule in traffic_rules:
                traffic_rule.update({"serviceClass": traffic.get('serviceClass'),
                                     "importance": traffic.get('importance')})
            rules.extend(traffic_rules)

        return rules, list(traffic_id_set)
