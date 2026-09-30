################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2024  flexiWAN Ltd.
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

import os
import subprocess
import sys
import time

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(code_root)
sys.path.append(test_root)
import fwtests

cli_path                          = __file__.replace('.py', '')
cli_file_initial_cfg              = os.path.join(cli_path, 'initial_cfg.cli')
cli_file_remove_tunnels           = os.path.join(cli_path, 'remove_tunnel.cli')

def get_vpp_tunnels():
    return subprocess.check_output('vppctl show vxlan tunnel', shell=True).decode()

def wait(resolution_interval):
    time.sleep(resolution_interval * 1.5)  # wait a bit more than the resolution interval to ensure the route is resolved

def test(fqdn_fast_resolution):
    resolution_interval = fqdn_fast_resolution[0]
    agent_conf_filename = fqdn_fast_resolution[1]
    fake_domain = 'fakedomainfakedomain.com' # "fakedomain.com" exists in the public DNS servers (:
    fake_ip = '9.9.9.9'
    fake_ip_2 = '10.10.10.10'

    with fwtests.TestFwagent() as agent:
        try:
            # take a copy of the /etc/hosts file
            os.system('cp /etc/hosts /etc/hosts.orig')

            (ok, err_str) = agent.cli(f'-f {cli_file_initial_cfg}', daemon=True, agent_conf_filename=agent_conf_filename)
            assert ok, err_str

            wait(resolution_interval)

            tunnels = get_vpp_tunnels()
            assert 'No vxlan tunnels' in tunnels, 'there should not be tunnels with unresolved destination'

            # Add fake ip to the fake domain and ensure that route is installed for this fake ip within 5 seconds
            os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
            wait(resolution_interval)
            tunnels = get_vpp_tunnels()
            assert fake_ip in tunnels, f'there should be tunnels with resolved ({fake_ip}) destination'

            # Change the fake ip in the hosts file and ensure that route is removed for this fake ip within 5 seconds
            os.system("sed -i '$d' /etc/hosts")
            os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
            wait(resolution_interval)
            tunnels = get_vpp_tunnels()
            assert fake_ip_2 in tunnels, f'there should be tunnels with updated resolved ({fake_ip_2}) destination'

            # remove the ip, and ensure there is no tunnel
            os.system("sed -i '$d' /etc/hosts")
            wait(resolution_interval)
            tunnels = get_vpp_tunnels()
            assert 'No vxlan tunnels' in tunnels, 'tunnel should be removed'

            # add the tunnel back, and check remove-tunnel request
            os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
            wait(resolution_interval)
            (ok, err_str) = agent.cli(f'-f {cli_file_remove_tunnels}')
            assert ok, err_str
        finally:
            # restore the original /etc/hosts file
            os.system('cp /etc/hosts.orig /etc/hosts')
            os.system('rm /etc/hosts.orig')

if __name__ == '__main__':
    test()
