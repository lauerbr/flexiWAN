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

"""Helpers to mask secrets (passwords, keys, tokens, etc.) before logging.

A dictionary key is considered sensitive if its last word (keys are split into
words by non-alphanumeric characters and camelCase boundaries) is one of
SECRET_WORDS, or if the key contains one of SECRET_SUBSTRINGS.
For example 'password', 'adminPassword', 'crypto-key', 'serverKey', 'psk',
'deviceToken', 'newPin', 'puk', 'certificate' are masked, while 'key-size',
'keyId', 'pin_state', 'hosts_to_ping' and 'wpa_key_mgmt' are not.
This module must not import other agent modules, so it could be used anywhere.
"""

import copy
import json
import re

REDACTED = '********'

SECRET_WORDS = frozenset([
    'password', 'passwd', 'pwd', 'passphrase', 'psk', 'key', 'secret', 'token',
    'pin', 'puk', 'cert', 'certificate', 'crt',
])
SECRET_SUBSTRINGS = ('password', 'passphrase', 'secret', 'privatekey', 'private_key', 'private-key')

_WORD_SPLIT_RE = re.compile(r'[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])')

def is_secret_key(key):
    """Return True if dictionary key name denotes sensitive value."""
    if not isinstance(key, str) or not key:
        return False
    lower = key.lower()
    if any(s in lower for s in SECRET_SUBSTRINGS):
        return True
    words = [w for w in _WORD_SPLIT_RE.split(key) if w]
    return bool(words) and words[-1].lower() in SECRET_WORDS

def _mask(value):
    # Keep non-sensitive types, e.g. 'bypass_certificate': False, as is.
    if value is None or isinstance(value, bool) or value == '' or value == {} or value == []:
        return value
    return REDACTED

def redact(obj):
    """Return deep copy of 'obj' (dict/list/tuple of any depth) where values
    of sensitive keys are replaced with REDACTED. The 'obj' is not modified.
    Strings that hold JSON objects/lists are redacted as well.
    """
    if isinstance(obj, dict):
        return { k: (_mask(v) if is_secret_key(k) else redact(v)) for k, v in obj.items() }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact(v) for v in obj)
    if isinstance(obj, str):
        return redact_str(obj)
    return copy.copy(obj) if isinstance(obj, (set, bytearray)) else obj

# Matches "key": "value" pairs in JSON-like / repr-like text. Keys are captured
# in group 'k', and values (string, number or bare word) in group 'v'.
_KV_RE = re.compile(r'''(?P<q>["'])(?P<k>[A-Za-z0-9_.\-]+)(?P=q)(?P<sep>\s*:\s*)(?P<v>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^,{}\[\]\s]+)''')

def redact_str(text):
    """Mask values of sensitive keys in a string that contains JSON or
    python representation of dictionaries (e.g. log lines).
    """
    if not isinstance(text, str) or not text:
        return text
    stripped = text.strip()
    if stripped[:1] in ('{', '[') and stripped[-1:] in ('}', ']'):
        try:
            return json.dumps(redact(json.loads(stripped)))
        except (ValueError, TypeError):
            pass

    def _replace(m):
        if not is_secret_key(m.group('k')):
            return m.group(0)
        v = m.group('v')
        if v in ('true', 'false', 'True', 'False', 'null', 'None', '""', "''"):
            return m.group(0)
        quote = v[0] if v[:1] in ('"', "'") else ''
        return f"{m.group('q')}{m.group('k')}{m.group('q')}{m.group('sep')}{quote}{REDACTED}{quote}"
    return _KV_RE.sub(_replace, text)

def dumps(obj, **kwargs):
    """json.dumps() of redacted copy of obj."""
    return json.dumps(redact(obj), **kwargs)
