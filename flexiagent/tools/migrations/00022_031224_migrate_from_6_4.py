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
import glob


globals = os.path.join(os.path.dirname(os.path.realpath(__file__)) , '..' , '..')
sys.path.append(globals)
import fwutils
import fwglobals

def _migrate_recovery_netplan_yamls(upgrade):
    fwglobals.initialize()
    if upgrade:
        old_extension = ".disabled"
        new_extension = fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT
    else:
        old_extension = fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT
        new_extension = ".disabled"
    for old_filename in glob.glob(f"/etc/netplan/*{old_extension}"):
        new_filename = old_filename.split(old_extension)[0] + new_extension
        shutil.move(old_filename, new_filename)
    fwglobals.finalize()


def migrate(prev_version=None, new_version=None, upgrade='upgrade'):
    try:
        if upgrade == 'upgrade' and fwutils.version_less_than(prev_version, '6.5.2'):
            print("* Migrating Recovery netplan file names to 6.5.3 format ...")
            _migrate_recovery_netplan_yamls(upgrade=True)

        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.5.3'):
            print("* Migrating Recovery netplan file names from 6.5.3 format ...")
            _migrate_recovery_netplan_yamls(upgrade=False)

    except Exception as e:
        print(f"Migration error: {__file__} : {e}")

if __name__ == "__main__":
    #
    # This code is used for unit testing of this script. It does not run on real installation.
    # Real installation imports this module and invokes the 'migrate()' method.
    #
    upgrade = True if len(sys.argv) < 2 or sys.argv[1] == "--upgrade" else False
    if upgrade:
        prev_version, new_version, upgrade = '6.4', '6.6', "upgrade"
    else:
        prev_version, new_version, upgrade = '6.6', '6.4', "downgrade"
    migrate(prev_version=prev_version, new_version=new_version, upgrade=upgrade)
