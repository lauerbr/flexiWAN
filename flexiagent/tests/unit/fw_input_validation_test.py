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

import pytest

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
sys.path.insert(0, AGENT_ROOT)

import fw_input_validation as v  # noqa: E402


def test_control_chars():
    assert v.has_control_chars("a\nb")
    assert v.has_control_chars("a\rb")
    assert v.has_control_chars("a\x00b")
    assert v.has_control_chars("a\x7fb")
    assert not v.has_control_chars("a b-c_d.e")

def test_safe_string():
    assert v.is_safe_string("my-password_1!")
    assert v.is_safe_string("with space")
    for bad in ['a"b', "a'b", "a`b", "a$b", "a\\b", "a\nb", "x\ny", 5, None]:
        assert not v.is_safe_string(bad), bad
    assert not v.is_safe_string("abcdef", max_len=3)
    assert v.is_safe_string("a;b", forbidden='')
    assert not v.is_safe_string("a;b", forbidden=';')

def test_shell_safe_word():
    assert v.is_shell_safe_word("eth0")
    assert v.is_shell_safe_word("pci:0000:00:08.00")
    for bad in ["", "a b", "a;b", "$(id)", "`id`", "a|b", "a>b", "a\nb", "a'b", 'a"b', "a&b", 1]:
        assert not v.is_shell_safe_word(bad), bad

def test_ip():
    assert v.is_valid_ip("1.2.3.4")
    assert v.is_valid_ip("::1")
    assert v.is_valid_ipv4("8.8.8.8")
    assert not v.is_valid_ipv4("::1")
    for bad in ["1.2.3.4; id", "1.2.3", " 1.2.3.4", "1.2.3.4\n", "", None, 16843009, "1.2.3.4/24"]:
        assert not v.is_valid_ip(bad), bad

def test_network():
    assert v.is_valid_network("10.0.0.0/24")
    assert v.is_valid_network("10.0.0.1/24")
    assert v.is_valid_network("10.0.0.1")
    assert not v.is_valid_network("10.0.0.1/24", strict=True)
    assert v.is_valid_network("2001:db8::/32", version=6)
    assert not v.is_valid_network("2001:db8::/32", version=4)
    for bad in ["10.0.0.0/33", "10.0.0.0/24;reboot", "", None, "10.0.0.0/24 "]:
        assert not v.is_valid_network(bad), bad

def test_fqdn_and_host():
    assert v.is_valid_fqdn("example.com")
    assert v.is_valid_fqdn("example.com.")
    assert v.is_valid_fqdn("my_host-1")
    for bad in ["", ".", "-a.com", "a..com", "a b.com", "a.com;id", "a" * 64 + ".com", "a$(id).com", None]:
        assert not v.is_valid_fqdn(bad), bad
    assert v.is_valid_host("1.1.1.1")
    assert v.is_valid_host("dns.google")
    assert not v.is_valid_host("1.1.1.1 -c 1000")

def test_int():
    assert v.is_valid_int(5)
    assert v.is_valid_int("5")
    assert v.is_valid_int("-5")
    assert v.is_valid_int(5, 1, 10)
    assert not v.is_valid_int(11, 1, 10)
    assert not v.is_valid_int(0, 1, 10)
    for bad in ["5; id", "5.0", "", None, True, 5.5, "1e3", " 5"]:
        assert not v.is_valid_int(bad), bad
    assert v.ensure_int("7", "lines", 1, 10) == 7
    with pytest.raises(ValueError):
        v.ensure_int("100 && reboot", "lines")

def test_debian_version():
    for good in ["6.3.40", "1:2.3-4ubuntu1", "6.3.40~rc1", "5.0.0+dfsg-1"]:
        assert v.is_valid_debian_version(good), good
    for bad in ["", "latest", "6.3.40; reboot", "6.3.40 && id", "$(id)", "6.3\n", "a.b", None]:
        assert not v.is_valid_debian_version(bad), bad

def test_ifname():
    for good in ["eth0", "wwan0", "GigabitEthernet0/8/0", "eth0.100", "vpp_tap-1"]:
        assert v.is_valid_ifname(good), good
    for bad in ["", "eth0;id", "eth 0", "eth0\n", "$(id)", None, "a" * 65]:
        assert not v.is_valid_ifname(bad), bad

def test_ping_host():
    for good in ["8.8.8.8", "google.com", "::1"]:
        assert v.is_valid_ping_host(good), good
    for bad in ["-f/etc/shadow", "8.8.8.8 -c 100", "8.8.8.8;id", "", None, "a\nb"]:
        assert not v.is_valid_ping_host(bad), bad

def test_ensure_helpers_raise():
    with pytest.raises(ValueError):
        v.ensure_ip("1.1.1.1;id")
    with pytest.raises(ValueError):
        v.ensure_network("bad")
    with pytest.raises(ValueError):
        v.ensure_host("a b")
    with pytest.raises(ValueError):
        v.ensure_debian_version("x; y")
    with pytest.raises(ValueError):
        v.ensure_safe_string('pass"word')
    with pytest.raises(ValueError):
        v.ensure_no_control_chars("a\nb")
    with pytest.raises(ValueError):
        v.ensure_shell_safe_word("a b")
    with pytest.raises(ValueError):
        v.ensure_ifname("eth0 up")
    assert v.ensure_ip("1.1.1.1") == "1.1.1.1"
    assert v.ensure_no_control_chars("a b") == "a b"
