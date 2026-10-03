#! /usr/bin/python3

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

# On upgrade this migration script updates the VPN server scripts.

import os
import shutil
import sys
import time

from sqlitedict import SqliteDict


globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwutils
from fwapplications_cfg import FwApplicationsCfg
from build.config import config

def _migrate_traffic_id_database(upgrade):
    old_db_path = f"{config.folders.data}/.traffic_identification.sqlite"
    new_db_path_traffic_id_map    = f"{old_db_path}.traffic_id_to_acl"
    new_db_path_category_map      = f"{old_db_path}.category_to_tid"
    new_db_path_traffic_class_map = f"{old_db_path}.traffic_class_to_tid"
    new_db_path_importance_map    = f"{old_db_path}.importance_to_tid"

    old = {
        "traffic_id_map":    SqliteDict(old_db_path, "traffic_id_map",    autocommit=True),
        "category_map":      SqliteDict(old_db_path, "category_map",      autocommit=True),
        "traffic_class_map": SqliteDict(old_db_path, "traffic_class_map", autocommit=True),
        "importance_map":    SqliteDict(old_db_path, "importance_map",    autocommit=True)
    }
    new = {
        "traffic_id_map":    SqliteDict(new_db_path_traffic_id_map,    autocommit=True),
        "category_map":      SqliteDict(new_db_path_category_map,      autocommit=True),
        "traffic_class_map": SqliteDict(new_db_path_traffic_class_map, autocommit=True),
        "importance_map":    SqliteDict(new_db_path_importance_map,    autocommit=True)
    }
    if upgrade:
        for table_name, table in old.items():
            for key, val in table.items():
                new[table_name][key] = val
    else:
        for table_name, table in new.items():
            for key, val in table.items():
                old[table_name][key] = val
                time.sleep(0.05)    # sleep 50 msec between writes to prevent 'database locked'

    for table in old.values():
        table.close()
    for table in new.values():
        table.close()
    if upgrade:
        os.remove(old_db_path)
    else:
        os.remove(new_db_path_traffic_id_map)
        os.remove(new_db_path_category_map)
        os.remove(new_db_path_traffic_class_map)
        os.remove(new_db_path_importance_map)

def _migrate_vpn_scripts():
    application_db_path = f"{config.folders.data}/.applications.sqlite"
    if os.path.exists(application_db_path):
        with FwApplicationsCfg(application_db_path) as application_cfg:
            apps = application_cfg.get_applications()

            for app in apps:
                identifier = app.get('identifier')
                if not identifier == 'com.flexiwan.remotevpn':
                    continue

                path = f'{config.folders.installation}/agent/applications/com_flexiwan_remotevpn/scripts'
                shutil.copyfile('{}/client-connect.py'.format(path), '/etc/openvpn/server/client-connect.py')


                os.system('killall openvpn') # it will be start again by our application watchdog


def migrate(prev_version=None, new_version=None, upgrade='upgrade'):
    try:
        if upgrade == 'upgrade' and fwutils.version_less_than(prev_version, '6.4.12'):
            print("* Migrating Traffic Identification database to 6.4.12 format ...")
            _migrate_traffic_id_database(upgrade=True)

            print("* Migrating Remote VPN scripts to 6.4.12 format ...")
            _migrate_vpn_scripts()

        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.4.12'):
            print("* Migrating Traffic Identification database from 6.4.12 format ...")
            _migrate_traffic_id_database(upgrade=False)

    except Exception as e:
        print(f"Migration error: {__file__} : {e}")

if __name__ == "__main__":
    #
    # This code is used for unit testing of this script. It does not run on real installation.
    # Real installation imports this module and invokes the 'migrate()' method.
    #
    upgrade = True if len(sys.argv) < 2 or sys.argv[1] == "--upgrade" else False
    if upgrade:
        prev_version, new_version, upgrade = '6.3', '6.5', "upgrade"
    else:
        prev_version, new_version, upgrade = '6.5', '6.3', "downgrade"
    migrate(prev_version=prev_version, new_version=new_version, upgrade=upgrade)
