################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2024 flexiWAN Ltd.
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

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , 'common')
sys.path.append(common_tools)

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)

import fwutils
from fwrouter_api import fwrouter_translators
from fwrouter_cfg import FwRouterCfg
from build.config import config

requests_db_path = f"{config.folders.data}/.requests.sqlite"

def migrate(prev_version=None, new_version=None, upgrade=None):
    try:
        if not os.path.exists(requests_db_path):
            return

        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.4.7'):

            with FwRouterCfg(requests_db_path) as router_cfg:

                router_cfg.set_translators(fwrouter_translators)

                loopback_interfaces = router_cfg.get_interfaces(device_type='loopback')
                for interface in loopback_interfaces:
                    dev_id  = interface['dev_id']
                    loopback_request = {
                        'message':   'add-interface',
                        'params':    interface
                    }
                    router_cfg.remove(loopback_request)
                    print(f"* Migrating : loopback interface {dev_id} removed")

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))

if __name__ == "__main__":
    migrate()
