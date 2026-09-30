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
import fw_input_validation
import fwutils

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
def _validate_link_monitor(params):
    """Validate link monitor parameters. The servers/urls and the timeout
    are used periodically in the fping command line, so they must be safe.
    """
    icmp = params.get('icmp')
    if icmp:
        for server in icmp.get('servers', []):
            fw_input_validation.ensure_host(server, 'link monitor server')
    http = params.get('http')
    if http:
        for url in http.get('urls', []):
            if not isinstance(url, str):
                raise ValueError(f"invalid link monitor url '{url!r}'")
            host = fwutils.url_extract_fqdn(url) or url
            if not fw_input_validation.is_valid_ping_host(host):
                raise ValueError(f"invalid link monitor url '{url!r}'")
    for conf in [icmp, http]:
        if not conf:
            continue
        if 'timeout' in conf:
            fw_input_validation.ensure_int(conf['timeout'], 'link monitor timeout', 1, 3600000)
        if 'attempts' in conf:
            fw_input_validation.ensure_int(conf['attempts'], 'link monitor attempts', 1, 100000)
        if 'threshold' in conf:
            fw_input_validation.ensure_int(conf['threshold'], 'link monitor threshold', 0, 100000)

def add_link_monitor(params):
    """Generate commands to add Link Monitor configuration.

    :param params:        Parameters from flexiManage.

    :returns: List of commands.
    """
    _validate_link_monitor(params)
    return [] # no need execution, just to have in DB (:

def modify_link_monitor(new_params, old_params):
    _validate_link_monitor(new_params)
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
