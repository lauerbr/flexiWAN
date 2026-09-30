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
import time

import pytest

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
sys.path.insert(0, AGENT_ROOT)

import fw_os_utils  # noqa: E402


@pytest.fixture
def sys_class_net(tmp_path, monkeypatch):
    """Builds fake /sys/class/net folder:
        enp0s3 -> ../../devices/pci0000:00/0000:00:03.0/net/enp0s3  (driver e1000, carrier up, wireless)
        br_lan -> ../../devices/virtual/net/br_lan                  (no driver, carrier file is not readable)
        bonding_masters                                             (regular file)
    """
    devices = tmp_path / 'devices'
    net = tmp_path / 'class_net'
    net.mkdir()

    enp = devices / 'pci0000:00' / '0000:00:03.0' / 'net' / 'enp0s3'
    enp.mkdir(parents=True)
    (enp / 'carrier').write_text('1\n')
    (enp / 'mtu').write_text('1500\n')
    (enp / 'wireless').mkdir()
    driver = devices / 'drivers' / 'e1000'
    driver.mkdir(parents=True)
    os.symlink(str(driver), str(enp / 'device'))   # simplified: 'device' points directly to folder with 'driver' link
    os.symlink(str(driver), str(driver / 'driver'))

    br = devices / 'virtual' / 'net' / 'br_lan'
    br.mkdir(parents=True)

    os.symlink(str(enp), str(net / 'enp0s3'))
    os.symlink(str(br), str(net / 'br_lan'))
    (net / 'bonding_masters').write_text('')

    monkeypatch.setattr(fw_os_utils, 'SYS_CLASS_NET', str(net))
    return net


def test_sys_class_net_lines(sys_class_net):
    lines = fw_os_utils.sys_class_net_lines()
    assert lines[0] == 'bonding_masters'
    assert lines[1].startswith('br_lan -> ') and lines[1].endswith('/devices/virtual/net/br_lan')
    assert lines[2].startswith('enp0s3 -> ') and lines[2].endswith('0000:00:03.0/net/enp0s3')
    # Lines should be parsed as lines of 'ls -l /sys/class/net'
    assert [l.split('/')[-1] for l in lines] == ['bonding_masters', 'br_lan', 'enp0s3']


def test_sys_class_net_grep(sys_class_net):
    assert [l.split('/')[-1] for l in fw_os_utils.sys_class_net_grep('0000:00:03.0')] == ['enp0s3']
    assert [l.split('/')[-1] for l in fw_os_utils.sys_class_net_grep('br_')] == ['br_lan']
    assert fw_os_utils.sys_class_net_grep('net', exclude='enp0s3')[-1].endswith('br_lan')
    assert fw_os_utils.sys_class_net_grep('no-such-interface') == []


def test_sys_class_net_grep_no_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(fw_os_utils, 'SYS_CLASS_NET', str(tmp_path / 'not-exists'))
    assert fw_os_utils.sys_class_net_grep('eth') == []
    with pytest.raises(OSError):
        fw_os_utils.sys_class_net_lines()


def test_sys_class_net_read(sys_class_net):
    assert fw_os_utils.sys_class_net_read('enp0s3', 'carrier') == '1'
    assert fw_os_utils.sys_class_net_read('enp0s3', 'mtu') == '1500'
    assert fw_os_utils.sys_class_net_read('br_lan', 'carrier') is None
    assert fw_os_utils.sys_class_net_read('no-such-interface', 'carrier') is None
    for bad in ['', None, '..', '../x']:
        assert fw_os_utils.sys_class_net_read(bad, 'carrier') is None


def test_sys_class_net_driver(sys_class_net):
    assert fw_os_utils.sys_class_net_driver('enp0s3') == 'e1000'
    assert fw_os_utils.sys_class_net_driver('br_lan') is None
    assert fw_os_utils.sys_class_net_driver('no-such-interface') is None
    assert fw_os_utils.sys_class_net_driver('') is None


def test_vpp_pid_is_cached(monkeypatch):
    calls = []
    def _pid_of(name):
        calls.append(name)
        return str(os.getpid()) if name == 'vpp_main' else None
    monkeypatch.setattr(fw_os_utils, 'pid_of', _pid_of)
    monkeypatch.setattr(fw_os_utils, '_vpp_pid_cache', None)
    alive = {'value': True}
    monkeypatch.setattr(fw_os_utils, '_is_vpp_pid_alive', lambda pid: alive['value'])

    assert fw_os_utils.vpp_pid() == str(os.getpid())
    assert calls == ['vpp_main']
    assert fw_os_utils.vpp_pid() == str(os.getpid())
    assert fw_os_utils.vpp_does_run()
    assert calls == ['vpp_main']            # served from cache

    alive['value'] = False                  # VPP was restarted/stopped
    assert fw_os_utils.vpp_pid() == str(os.getpid())
    assert calls == ['vpp_main', 'vpp_main']


def test_vpp_pid_not_running(monkeypatch):
    calls = []
    def _pid_of(name):
        calls.append(name)
        return None
    monkeypatch.setattr(fw_os_utils, 'pid_of', _pid_of)
    monkeypatch.setattr(fw_os_utils, '_vpp_pid_cache', None)
    assert fw_os_utils.vpp_pid() is None
    assert not fw_os_utils.vpp_does_run()
    assert calls == ['vpp_main', 'vpp', 'vpp_main', 'vpp']   # negative result is not cached


def test_vpp_pid_multiple_pids_not_cached(monkeypatch):
    monkeypatch.setattr(fw_os_utils, 'pid_of', lambda name: '10\n11' if name == 'vpp_main' else None)
    monkeypatch.setattr(fw_os_utils, '_vpp_pid_cache', None)
    assert fw_os_utils.vpp_pid() == '10\n11'
    assert fw_os_utils._vpp_pid_cache is None


def test_is_vpp_pid_alive(monkeypatch):
    # Current process exists, but it is not VPP
    assert not fw_os_utils._is_vpp_pid_alive(str(os.getpid()))
    monkeypatch.setattr(fw_os_utils, '_VPP_PROCESS_NAMES', (open(f'/proc/{os.getpid()}/comm').read().strip(),))
    assert fw_os_utils._is_vpp_pid_alive(str(os.getpid()))
    assert not fw_os_utils._is_vpp_pid_alive('not-a-pid')
    assert not fw_os_utils._is_vpp_pid_alive(None)


def test_yaml_file_cache(tmp_path):
    cache = fw_os_utils.FwYamlFileCache()
    fname = str(tmp_path / 'a.yaml')
    with open(fname, 'w') as f:
        f.write('network:\n  version: 2\n')

    first = cache.load(fname)
    assert first == {'network': {'version': 2}}
    assert cache.load(fname) is first        # served from cache

    time.sleep(0.01)
    with open(fname, 'w') as f:
        f.write('network:\n  version: 33\n')
    assert cache.load(fname) == {'network': {'version': 33}}

    cache.forget_except([])
    assert cache.cache == {}
    os.remove(fname)
    with pytest.raises(OSError):
        cache.load(fname)
