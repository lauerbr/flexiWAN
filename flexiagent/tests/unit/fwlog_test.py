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
import types

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
sys.path.insert(0, AGENT_ROOT)

import fwlog  # noqa: E402


class _CaptureLog(fwlog.Fwlog):
    def __init__(self, level):
        fwlog.Fwlog.__init__(self, 'capture', level)
        self.lines = []

    def _log(self, log_message, to_terminal=True, to_syslog=True, truncate_long_line='default', print_bt=False):
        self.lines.append((log_message, to_terminal, to_syslog, truncate_long_line, print_bt))


def _log_all(log):
    log.excep('e1')
    log.error('e2', to_terminal=False)
    log.warning('w')
    log.info('i', to_syslog=False)
    log.debug('d', print_bt=True)
    log.trace('t')


def test_levels_and_formatting():
    log = _CaptureLog(fwlog.FWLOG_LEVEL_TRACE)
    _log_all(log)
    assert log.lines == [
        ('excep: e1',            True,  True,  False,     False),
        ('error: e2',            False, True,  False,     False),
        ('*** warning: w ***',   True,  True,  False,     False),
        ('i',                    True,  False, 'default', False),
        ('d',                    True,  True,  'default', True),
        ('t',                    True,  True,  'default', False),
    ]

def test_level_info():
    log = _CaptureLog(fwlog.FWLOG_LEVEL_INFO)
    _log_all(log)
    assert [l[0] for l in log.lines] == ['excep: e1', 'error: e2', '*** warning: w ***', 'i']
    assert not log.is_debug_enabled()

def test_level_debug():
    log = _CaptureLog(fwlog.FWLOG_LEVEL_DEBUG)
    _log_all(log)
    assert [l[0] for l in log.lines] == ['excep: e1', 'error: e2', '*** warning: w ***', 'i', 'd']
    assert log.is_debug_enabled()

def test_object_logger_is_debug_enabled(monkeypatch):
    # FwObjectLogger imports fwglobals, which pulls the whole agent. Replace it with stub.
    if 'fwglobals' not in sys.modules:
        monkeypatch.setitem(sys.modules, 'fwglobals', types.SimpleNamespace(g_initialized=0))
    log = _CaptureLog(fwlog.FWLOG_LEVEL_INFO)
    obj_log = fwlog.FwObjectLogger('obj', log=log)
    assert not obj_log.is_debug_enabled()
    log.set_level(fwlog.FWLOG_LEVEL_DEBUG)
    assert obj_log.is_debug_enabled()
    obj_log.debug('x')
    assert log.lines[-1][0] == 'obj: x'
