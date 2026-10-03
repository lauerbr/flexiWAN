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

import glob
import os
import sys

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
sys.path.append(code_root)
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests
import fw_os_utils

cli_path = __file__.replace('.py', '')

def test():
     with fwtests.TestFwagent() as agent:

        steps = sorted(glob.glob(cli_path + '/' + '*.cli'))

        # 01-Install NTOP-NG
        step = steps[0]
        assert '01_install.cli' in step, "Test 01 not found"
        (ok, err_str) = agent.cli(f'-f {step}', check_log=True)
        assert ok, err_str

        # Check installation exists
        installed = os.popen("dpkg -l | grep -E '^ii' | grep -E 'ii\s+ntopng\s'").read()
        dir_is_empty = os.path.exists('/etc/ntopng') and len(os.listdir('/etc/ntopng')) == 0
        assert installed and not dir_is_empty, "NTOP package not found"

        # 02-Configure NTOP-NG
        step = steps[1]
        assert '02_configure.cli' in step, "Test 02 not found"
        (ok, err_str) = agent.cli(f'-f {step}', check_log=True)
        assert ok, err_str

        # 03-Start router
        step = steps[2]
        assert '03_start-router.cli' in step, "Test 03 not found"
        (ok, err_str) = agent.cli(f'-f {step}', daemon=True, check_log=True)
        assert ok, err_str

        # Check router is running
        router_is_running = fw_os_utils.vpp_does_run()
        assert router_is_running

        # 04-Confiure another interface, change serverPort, password and affinity
        step = steps[3]
        assert '04_configure2.cli' in step, "Test 04 not found"
        (ok, err_str) = agent.cli(f'-f {step}', check_log=True)
        assert ok, err_str

        # 05-Stop router
        step = steps[4]
        assert '05_stop-router.cli' in step, "Test 05 not found"
        (ok, err_str) = agent.cli(f'-f {step}', check_log=True)
        assert ok, err_str

        # Check router is not running
        router_is_running = fw_os_utils.vpp_does_run()
        assert not router_is_running

        # 06-Uninstall application
        step = steps[5]
        assert '06_uninstall.cli' in step, "Test 06 not found"
        (ok, err_str) = agent.cli(f'-f {step}', check_log=True)
        assert ok, err_str

if __name__ == '__main__':
    test()
