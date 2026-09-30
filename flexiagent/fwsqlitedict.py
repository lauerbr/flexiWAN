#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
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

import pickle
import sqlite3

from sqlitedict import SqliteDict

from fwobject import FwObject
from fw_os_utils import touch_private_file


def _decode(obj):
    """Deserialize objects retrieved from SQLite."""
    return pickle.loads(bytes(obj), encoding="latin1")


def _encode(obj):
    """Serialize objects to binary format."""
    return sqlite3.Binary(pickle.dumps(obj, protocol=2))


class FwSqliteDict(FwObject, SqliteDict):
    """This is base DB class implementation, based on SqliteDict."""

    def __init__(self, db_filename, table_name=None, autocommit=True):
        # The databases might store secrets (tunnel keys, passwords, etc),
        # so ensure they are not readable by other users.
        if db_filename and db_filename != ':memory:':
            touch_private_file(db_filename)
        if table_name:
            SqliteDict.__init__(self, filename=db_filename, tablename=table_name, autocommit=autocommit, encode=_encode, decode=_decode)
        else:
            SqliteDict.__init__(self, filename=db_filename, autocommit=autocommit, encode=_encode, decode=_decode)
        FwObject.__init__(self)

    def initialize(self):
        super().initialize()  # supper() assumes the "FwObject, SqliteDict" order of inheritance!

    def finalize(self):
        """Close DB

        :returns: None.
        """
        self.close()
        super().finalize()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        for req_key in self:
            del self[req_key]

    def fetch(self, path, default_val=None):
        nodes    = path.split('/')
        sub_tree = self
        for node in nodes:
            if not node in sub_tree:
                return default_val
            sub_tree = sub_tree[node]
        return sub_tree   # the last sub_tree is a leaf node that represents the requested value

    def put(self, path, val):

        nodes = path.split('/')
        if len(nodes) == 1:
            self[nodes[0]] = val
            return

        # sqlitedict cannot know when a mutable SqliteDict-backed entry was modified in RAM.
        # So, we explicitly assign the mutated object back to SqliteDict.
        # For details see https://github.com/piskvorky/sqlitedict#more.
        # So we fetch the root tree, modify it and then sent back. If it does not exists, create it.
        #
        db = self.get(nodes[0], {})

        # Go from the root to the leaf's parent while building internal nodes if needed
        #
        sub_tree = db
        for node in nodes[1:-1]:
            if not node in sub_tree:
                sub_tree.update({node: {}})
            sub_tree = sub_tree[node]
        sub_tree.update({nodes[-1]: val})

        self[nodes[0]] = db  # replace the top level dict


    def delete(self, path):

        nodes = path.split('/')
        if len(nodes) == 1:
            self[nodes[0]] = {}
            return

        # sqlitedict cannot know when a mutable SqliteDict-backed entry was modified in RAM.
        # So, we explicitly assign the mutated object back to SqliteDict.
        # For details see https://github.com/piskvorky/sqlitedict#more.
        # So we fetch the root tree, modify it and then sent back. If it does not exists, create it.
        #
        db = self.get(nodes[0], {})

        sub_tree = db
        for node in nodes[1:-1]:
            if not node in sub_tree:
                return
            sub_tree = sub_tree[node]
        sub_tree.pop(nodes[-1], None)    # 'None' prevents exception if key does not exist

        self[nodes[0]] = db  # replace the top level dict


    def list_insert(self, path, elem, at_head=True):
        l = self.fetch(path, [])
        idx = 0 if at_head else len(l)
        l.insert(idx, elem)
        self.put(path, l)

    def list_pop(self, path):
        l = self.fetch(path)
        if not l:
            return None
        elem = l.pop(0)
        self.put(path, l)
        return elem

