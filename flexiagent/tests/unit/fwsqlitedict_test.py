################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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

# Standalone unit tests - no VPP or agent installation is needed:
#   python3 -m pytest tests/unit

import os
import sys
import threading
import types

import pytest

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
sys.path.insert(0, AGENT_ROOT)

pytest.importorskip('sqlitedict')


@pytest.fixture
def db(tmp_path, monkeypatch):
    # FwObject imports fwglobals, which pulls the whole agent. Replace it with
    # not initialized stub, so the object logs into syslog.
    if 'fwglobals' not in sys.modules:
        monkeypatch.setitem(sys.modules, 'fwglobals', types.SimpleNamespace(g_initialized=0))
    from fwsqlitedict import FwSqliteDict
    d = FwSqliteDict(str(tmp_path / 'test.sqlite'))
    yield d
    d.close()


def test_put_fetch_delete(db):
    db.put('a/b/c', 1)
    db.put('a/b/d', 2)
    assert db.fetch('a/b') == {'c': 1, 'd': 2}
    assert db.fetch('a/x', 'default') == 'default'
    db.delete('a/b/c')
    assert db.fetch('a/b') == {'d': 2}
    db.delete('a/no/such/path')
    assert db.fetch('a') == {'b': {'d': 2}}


def test_list_insert_pop(db):
    db.list_insert('q/items', 1)
    db.list_insert('q/items', 2)
    db.list_insert('q/items', 3, at_head=False)
    assert db.fetch('q/items') == [2, 1, 3]
    assert db.list_pop('q/items') == 2
    assert db.fetch('q/items') == [1, 3]


def test_concurrent_put_no_lost_updates(db):
    # put() reads the top level tree, modifies it and writes it back,
    # so without serialization simultaneous updates of different sub-keys
    # of the same top level key are lost.
    num_threads, num_puts = 8, 25

    def _worker(tid):
        for i in range(num_puts):
            db.put(f'root/t{tid}/k{i}', i)

    threads = [threading.Thread(target=_worker, args=(t,)) for t in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    root = db.fetch('root')
    assert sorted(root.keys()) == sorted(f't{t}' for t in range(num_threads))
    for t in range(num_threads):
        assert root[f't{t}'] == {f'k{i}': i for i in range(num_puts)}
