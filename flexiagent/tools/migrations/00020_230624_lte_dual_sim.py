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
from fwsystem_api import fwsystem_translators
from fwsystem_cfg import FwSystemCfg
from fwlte import FwModemManager
from build.config import config

requests_db_path = f"{config.folders.data}/.system.sqlite"

def migrate(prev_version=None, new_version=None, upgrade=True):
    try:
        if not os.path.exists(requests_db_path):
            return
        with FwSystemCfg(requests_db_path) as system_cfg:
            system_cfg.set_translators(fwsystem_translators)
            add_lte_requests = system_cfg.get_lte()

            if not add_lte_requests:
                return

            is_add    = upgrade == 'upgrade'   and fwutils.version_less_than(prev_version, '6.4.14')
            is_remove = upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.4.14')

            if not is_add and not is_remove:
                return

            modems = FwModemManager(scan=True)
            for add_lte_request in add_lte_requests:
                if is_add:
                    dev_id = add_lte_request.get('dev_id')
                    modem = modems.get(dev_id)
                    active_slot_str = str(modem.active_slot)
                    new_params = {
                        "metric": add_lte_request.get('metric'),
                        "dev_id": add_lte_request.get('dev_id'),
                        "primarySlot": active_slot_str,
                        "automaticSwitchover": False,
                        "tryPrimaryAfter": "",
                        "slots": {
                            active_slot_str : {
                                "apn": add_lte_request.get('apn'),
                                "pin": add_lte_request.get('pin'),
                                "auth": add_lte_request.get('auth'),
                                "user": add_lte_request.get('user'),
                                "password": add_lte_request.get('password')
                            }
                        }
                    }
                else:
                    primary_slot = add_lte_request.get('primarySlot')
                    config       = add_lte_request.get('slots', {}).get(primary_slot)
                    new_params = {
                        "metric": add_lte_request.get('metric'),
                        "dev_id": add_lte_request.get('dev_id'),
                        "enable": True,
                        "apn": config.get('apn'),
                        "pin": config.get('pin'),
                        "auth": config.get('auth'),
                        "user": config.get('user'),
                        "password": config.get('password')
                    }

                new_lte_request = {
                    'message':   'add-lte',
                    'params':    new_params
                }
                system_cfg.update(new_lte_request, [], False)

            print(f"* Migrating : {'Adding' if is_add else 'Removing'} LTE Dual SIM params")

    except Exception as e:
        print("Migration error: %s : %s" % (__file__, str(e)))


if __name__ == "__main__":
    migrate()
