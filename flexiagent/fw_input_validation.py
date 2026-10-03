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

"""Validation helpers for values received from flexiManage (or other untrusted
sources) that end up in command lines or configuration files of other programs.

The is_*() functions return True/False. The ensure_*() functions raise
ValueError with descriptive message if the value is not valid and return the
value (converted to the appropriate type, if applicable) otherwise.
This module must not import other agent modules, so it could be used anywhere.
"""

import ipaddress
import re

_FQDN_LABEL_RE      = re.compile(r'^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$')
_DEBIAN_VERSION_RE  = re.compile(r'^([0-9]+:)?[0-9][A-Za-z0-9.+~-]*$')
_IFNAME_RE          = re.compile(r'^[A-Za-z0-9_.:@/-]{1,64}$')
_SHELL_UNSAFE_CHARS = set('"\'`$\\;&|<>(){}*?![]#~\n\r')

def has_control_chars(value):
    """Return True if string has ASCII control characters (including newlines)."""
    return any(ord(c) < 32 or ord(c) == 127 for c in str(value))

def is_safe_string(value, forbidden='"\'`$\\', max_len=None):
    """Return True if value is a string without control characters
    (newlines included) and without any of the 'forbidden' characters.
    By default quotes, backticks, dollar sign and backslash are forbidden.
    """
    if not isinstance(value, str):
        return False
    if max_len is not None and len(value) > max_len:
        return False
    if has_control_chars(value):
        return False
    return not any(c in forbidden for c in value)

def is_shell_safe_word(value):
    """Return True if value can't be interpreted by shell as anything but
    a single plain word (no spaces, quotes, meta-characters or control chars).
    """
    if not isinstance(value, str) or value == '':
        return False
    if has_control_chars(value) or ' ' in value:
        return False
    return not any(c in _SHELL_UNSAFE_CHARS for c in value)

def is_valid_ip(value, version=None):
    """Return True if value is a valid IP address (4, 6 or any if version is None)."""
    if not isinstance(value, str):
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return version is None or ip.version == version

def is_valid_ipv4(value):
    return is_valid_ip(value, version=4)

def is_valid_network(value, version=None, strict=False):
    """Return True if value is a valid IP address or IP network in CIDR notation,
    e.g. '10.0.0.0/24' or '10.0.0.1/24' (host bits are allowed if strict is False).
    """
    if not isinstance(value, str) or value != value.strip() or value == '':
        return False
    try:
        net = ipaddress.ip_network(value, strict=strict)
    except ValueError:
        return False
    return version is None or net.version == version

def is_valid_fqdn(value):
    """Return True if value is a syntactically valid host name / FQDN."""
    if not isinstance(value, str) or not value or len(value) > 253:
        return False
    name = value[:-1] if value.endswith('.') else value
    if not name:
        return False
    return all(_FQDN_LABEL_RE.fullmatch(label) for label in name.split('.'))

def is_valid_host(value):
    """Return True if value is either valid IP address or valid FQDN."""
    return is_valid_ip(value) or is_valid_fqdn(value)

def is_valid_int(value, min_val=None, max_val=None):
    """Return True if value is integer (or string that consists of digits only,
    optionally prefixed by '-') and it fits into the [min_val, max_val] range.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        if not re.fullmatch(r'-?[0-9]+', value):
            return False
        value = int(value)
    elif not isinstance(value, int):
        return False
    if min_val is not None and value < min_val:
        return False
    if max_val is not None and value > max_val:
        return False
    return True

def is_valid_debian_version(value):
    """Return True if value is valid Debian package version, e.g. '6.3.40' or '1:2.3-4ubuntu1'."""
    return isinstance(value, str) and len(value) <= 128 and bool(_DEBIAN_VERSION_RE.fullmatch(value))

def is_valid_ifname(value):
    """Return True if value looks as Linux or VPP interface name,
    e.g. 'eth0', 'vpp1', 'wwan0', 'GigabitEthernet0/8/0', 'tap_wwan0', 'eth0.100'."""
    return isinstance(value, str) and bool(_IFNAME_RE.fullmatch(value))


def is_valid_ping_host(value):
    """Return True if value can be safely passed to ping/fping as host argument:
    a single word without shell special characters that is not an option."""
    return is_shell_safe_word(value) and not value.startswith('-')

def _ensure(ok, name, value, what):
    if not ok:
        raise ValueError(f"invalid {name} '{value!r}': {what} is expected")
    return value

def ensure_safe_string(value, name='value', forbidden='"\'`$\\', max_len=None):
    return _ensure(is_safe_string(value, forbidden, max_len), name, value,
                   f"string without control characters and without {forbidden!r}")

def ensure_no_control_chars(value, name='value'):
    return _ensure(isinstance(value, str) and not has_control_chars(value), name, value,
                   "string without control characters (e.g. newlines)")

def ensure_shell_safe_word(value, name='value'):
    return _ensure(is_shell_safe_word(value), name, value, "single word without shell special characters")

def ensure_ip(value, name='ip', version=None):
    return _ensure(is_valid_ip(value, version), name, value, "IP address")

def ensure_network(value, name='network', version=None):
    return _ensure(is_valid_network(value, version), name, value, "IP address or network")

def ensure_host(value, name='host'):
    return _ensure(is_valid_host(value), name, value, "IP address or FQDN")

def ensure_int(value, name='value', min_val=None, max_val=None):
    _ensure(is_valid_int(value, min_val, max_val), name, value, f"integer in range [{min_val},{max_val}]")
    return int(value)

def ensure_debian_version(value, name='version'):
    return _ensure(is_valid_debian_version(value), name, value, "debian package version")

def ensure_ifname(value, name='interface name'):
    return _ensure(is_valid_ifname(value), name, value, "interface name")
