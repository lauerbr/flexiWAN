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

import copy
import json
import os
import sys

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..'))
sys.path.insert(0, AGENT_ROOT)

import fw_redact  # noqa: E402
from fw_redact import REDACTED, is_secret_key, redact, redact_str  # noqa: E402


def test_is_secret_key():
    for key in ['password', 'Password', 'adminPassword', 'wpa_passphrase', 'psk', 'key',
                'crypto-key', 'integr-key', 'serverKey', 'tlsKey', 'dhKey', 'caCrt',
                'secret', 'client_secret', 'token', 'deviceToken', 'device_token',
                'pin', 'newPin', 'currentPin', 'puk', 'certificate', 'cert', 'PSK',
                'wep_default_key', 'private_key_pem']:
        assert is_secret_key(key), key
    for key in ['key-size', 'keyId', 'pin_state', 'hosts_to_ping', 'wpa_key_mgmt',
                'keys_to_acls', 'certificateExpiration', 'remote-cert-applied',
                'vpnTmpTokenTime', 'mapping', 'ping_timeout', 'message', 'ok', '', None, 5]:
        assert not is_secret_key(key), key

def test_redact_nested():
    request = {
        'message': 'add-tunnel',
        'params': {
            'ipsec': {
                'local-sa': {'crypto-key': 'abcd', 'integr-key': 'efgh', 'spi': 1},
                'remote-sa': {'crypto-key': 'ijkl'},
            },
            'bgp': {'neighbors': [{'ip': '1.1.1.1', 'password': 'secret1'}]},
            'lte': {'apn': 'internet', 'pin': '1234', 'puk': '5678'},
            'wifi': {'2.4GHz': {'ssid': 'net', 'password': 'wifipass'}},
            'bypass_certificate': False,
            'emptyPassword': '',
        },
    }
    orig = copy.deepcopy(request)
    out = redact(request)
    assert request == orig, "input must not be modified"
    assert out['message'] == 'add-tunnel'
    assert out['params']['ipsec']['local-sa'] == {'crypto-key': REDACTED, 'integr-key': REDACTED, 'spi': 1}
    assert out['params']['ipsec']['remote-sa']['crypto-key'] == REDACTED
    assert out['params']['bgp']['neighbors'][0] == {'ip': '1.1.1.1', 'password': REDACTED}
    assert out['params']['lte'] == {'apn': 'internet', 'pin': REDACTED, 'puk': REDACTED}
    assert out['params']['wifi']['2.4GHz']['password'] == REDACTED
    assert out['params']['bypass_certificate'] is False
    assert out['params']['emptyPassword'] == ''
    dumped = json.dumps(out)
    for secret in ['abcd', 'efgh', 'ijkl', 'secret1', '1234', '5678', 'wifipass']:
        assert secret not in dumped

def test_redact_list_of_requests_and_dict_value():
    out = redact([{'message': 'x', 'params': {'serverKey': {'pem': 'PRIVATE'}}}])
    assert out[0]['params']['serverKey'] == REDACTED

def test_redact_str_json():
    line = json.dumps({'token': 'tok123', 'a': {'password': 'p"w'}})
    out = redact_str(line)
    assert 'tok123' not in out and 'p\\"w' not in out
    assert json.loads(out)['a']['password'] == REDACTED

def test_redact_str_text():
    line = "seq=1: request {'message': 'add-lte', 'params': {'pin': '1234', 'apn': 'x', 'password': \"a'b\", 'enable': True}}"
    out = redact_str(line)
    assert '1234' not in out and "a'b" not in out
    assert "'apn': 'x'" in out
    assert "'enable': True" in out
    line = 'Registering to https://x with: {"token": "eyJabc.def", "serial": "123"}'
    out = redact_str(line)
    assert 'eyJabc' not in out and '"serial": "123"' in out
    line = '"psk": 12345, "other": 1'
    assert '12345' not in redact_str(line)

def test_redact_str_command_line():
    line = "vtysh_cmd failed: sudo /usr/bin/vtysh -c configure -c 'neighbor 1.1.1.1 password s3cr3t' -c x"
    out = redact_str(line)
    assert 's3cr3t' not in out
    assert "neighbor 1.1.1.1 password" in out
    out = redact_str("commands=['router bgp 1', 'neighbor 1.1.1.1 password abc']")
    assert 'abc' not in out and "'router bgp 1'" in out

def test_dumps():
    assert 'x1' not in fw_redact.dumps({'password': 'x1'})
    assert redact('plain text') == 'plain text'
    assert redact(5) == 5
    assert redact(None) is None
