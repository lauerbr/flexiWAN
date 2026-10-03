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

# On downgrade, this migration script fixes potentially corrupted jobs database,
# with missing "received_at" field. In case it's missing, it uses the "timestamp"
# field to fill it (in newer agent versions, the "received_at" won't be stored
# in the database, but only the "timestamp").

import os
import sys
import shutil

from datetime import datetime

globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwutils

from fwsqlitedict import FwSqliteDict
from fwapplications_cfg import FwApplicationsCfg
from fwapplications_api import fwapplication_translators
from build.config import config

from build.config import config

application_db_path = f"{config.folders.data}/.applications.sqlite"

def _remove_vpn_from_db():
    if os.path.exists(application_db_path):
        with FwApplicationsCfg(application_db_path) as application_cfg:
            application_cfg.set_translators(fwapplication_translators)
            apps = application_cfg.get_applications()

            for app in apps:
                identifier = app.get('identifier')
                if not identifier == 'com.flexiwan.remotevpn':
                    continue

                os.system(f"rm -rf /etc/openvpn/server/*")
                os.system(f"apt-get remove -y openvpn")

                application_cfg.remove({
                    'message': 'remove-app-install',
                    'params': {
                        'identifier': identifier
                    }
                })

                application_cfg.remove({
                    'message': 'remove-app-config',
                    'params': {
                        'identifier': identifier
                    }
                })

def migrate(prev_version=None, new_version=None, upgrade='upgrade'):
    print(f"Migrate Enter, {upgrade}, {new_version}")
    try:
        # When the *new* version is <= 6.5.13 and the *old* version is >= 6.5.14,
        # we must remove the VPN configuration from the DB to allow proper regeneration by the downgraded version.
        #
        # This logic runs during the 'downgrade' step. Unlike the upgrade path, we don’t have access to the new version’s
        # files at this point — only to those of the current (old) version.
        # Since version 6.5.13 doesn’t recreate the VPN scripts on start, we must trigger their regeneration
        # in order to have the proper files.
        #
        # By removing the VPN entry from the DB, the subsequent 'sync' step that follows the downgrade process,
        # will detect the missing configuration and re-run the installation process
        # according to the expectations of the new_version.
        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.5.14'):
            print("* Removing VPN From DB ...")
            _remove_vpn_from_db()

    except Exception as e:
        print(f"Migration error: {__file__} : {e}")

if __name__ == "__main__":
    #
    # This code is used for unit testing of this script. It does not run on real installation.
    # Real installation imports this module and invokes the 'migrate()' method.
    # Tested using this example: python 00022_120824_migrate_from_6_5.py --downgrade
    #
    print(f"main Enter {len(sys.argv)}")
    upgrade = True if len(sys.argv) < 2 or sys.argv[1] == "--upgrade" else False
    if upgrade:
        prev_version, new_version, upgrade = '6.4', '6.5', "upgrade"
    else:
        prev_version, new_version, upgrade = '6.5', '6.4.1-500', "downgrade"
    migrate(prev_version=prev_version, new_version=new_version, upgrade=upgrade)
