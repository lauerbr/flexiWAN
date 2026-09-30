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
import fwglobals

# {
#   "entity": "agent",
#   "message": "add-link-monitor",
#   "params": {
#     "id": "6665bbff9c180f8bc4c0f322",
#     "icmp": {
#       "servers": [
#         "8.8.8.8",
#         "1.1.1.1"
#       ],
#       "timeout": 1000,
#       "attempts": 20,
#       "threshold": 12
#     }
#   }
# }
# {
#   "entity": "agent",
#   "message": "add-link-monitor",
#   "params": {
#     "id": "6665bbff9c180f8bc4c0f321",
#     "http": {
#       "urls": [
#         "http://example.com/api/get",
#         "google.com"
#       ],
#       "timeout": 1000,
#       "attempts": 20,
#       "threshold": 12
#     }
#   }
# }
def add_link_monitor(params):
    """Generate commands to add Link Monitor configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    return [] # no need execution, just to have in DB (:

def modify_link_monitor(new_params, old_params):
    return []

modify_link_monitor_supported_params = {
    "icmp": None,
    "http": None
}

def get_request_key(params):
    """Get add-link-monitor key.

    :param params:        Parameters from flexiManage.

    :returns: request key for add-link-monitor request.
    """
    return 'add-link-monitor-' + params['id']
