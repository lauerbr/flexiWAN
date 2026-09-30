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

def _migrate_jobs_database():
    db_path = f"{config.folders.data}/.jobs.sqlite"
    if not os.path.exists(db_path):
        print(f"Database does not exist at {db_path}")
        return

    with FwSqliteDict(db_path) as jobs_db:
        for job_id, job in jobs_db.items():
            received_at = job.get('received_at', None)
            timestamp = job.get('timestamp', 0)
            if received_at:
                continue
            print(f"Fixing {job_id}: before {received_at}, {timestamp}")
            dt = datetime.fromtimestamp(timestamp)
            received_at = dt.strftime('%b %d, %Y, %I:%M %p')
            print(f"Fixing {job_id}: after {received_at}, {timestamp}")
            job["received_at"] = received_at
            jobs_db[job_id] = job # The underneath sqldict does not support in-memory modification, so replace whole element

def _migrate_remove_ntopng():
    application_db_path = f"{config.folders.data}/.applications.sqlite"
    if os.path.exists(application_db_path):
        with FwApplicationsCfg(application_db_path) as application_cfg:
            application_cfg.set_translators(fwapplication_translators)
            apps = application_cfg.dump(types=[
                'add-app-install',
                'add-app-config'
            ], escape=None, full=True, keys=True)
            for app in apps:
                identifier = app['params'].get('identifier')
                if identifier == 'com.flexiwan.monitorntop':
                    application_cfg.remove(app)
    shutil.rmtree(f'{config.folders.installation}/agent/applications/com_flexiwan_monitorntop')

def migrate(prev_version=None, new_version=None, upgrade='upgrade'):
    print(f"Migrate Enter, {upgrade}, {new_version}")
    try:
        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.5.1'):
            print("* Migrating Jobs database from 6.5.1 format ...")
            _migrate_jobs_database()
        if upgrade == 'downgrade' and fwutils.version_less_than(new_version, '6.5.5'):
            print("* Migrating NTOP-NG removal ...")
            _migrate_remove_ntopng()
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
