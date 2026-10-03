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
cli_file_fqdn_routes_add          = os.path.join(cli_path, 'fqdn_routes_add.cli')
cli_file_fqdn_routes_remove       = os.path.join(cli_path, 'fqdn_routes_remove.cli')

def get_routing_table():
    return subprocess.check_output('ip r', shell=True).decode()

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

            # Take copy of the routing table before the FQDN route
            start_routing_table = get_routing_table()

            # Install the route with the fake domain
            (ok, err_str) = agent.cli(f'-f {cli_file_fqdn_routes_add}')
            assert ok, err_str

            # Since the fake domain should not be resolved. Wait a bit and ensure no route was added
            wait(resolution_interval)
            unresolved_routing_table = get_routing_table()
            assert unresolved_routing_table == start_routing_table, 'Routing table should be the same as domain is unresolved'

            # Add fake ip to the fake domain and ensure that route is installed for this fake ip within 5 seconds
            os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
            wait(resolution_interval)
            resolved_routing_table = get_routing_table()
            assert fake_ip in resolved_routing_table, f'{fake_ip} does not exist in the routing table'

            # Now, let's check that "check_reinstall_static_route" functionality is working with FQDN.
            # Let's remove the route manually and check after 5 seconds that agent reinstall it
            os.system(f'ip route del {fake_ip}')
            wait(resolution_interval)
            reinstalled_routing_table = get_routing_table()
            assert reinstalled_routing_table == resolved_routing_table, f'agent does not reinstall the removed {fake_ip}'

            # Change the fake ip in the hosts file and ensure that route is removed for this fake ip within 5 seconds
            os.system("sed -i '$d' /etc/hosts")
            os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
            wait(resolution_interval)
            updated_routing_table = get_routing_table()
            assert fake_ip not in updated_routing_table, f'{fake_ip} exists in the routing table but it should be unresolved and removed from routing table'
            assert fake_ip_2 in updated_routing_table, f'{fake_ip_2} does not exist in the routing table'

            # Remove the fake IP and keep the domain unresolved, and ensure that route is removed
            os.system("sed -i '$d' /etc/hosts")
            wait(resolution_interval)
            unresolved_routing_table = get_routing_table()
            assert unresolved_routing_table == start_routing_table, 'unresolved route exists in the routing table'

            # Now, let's check multiple IPs resolved for one domain
            os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
            os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
            wait(resolution_interval)
            multiple_routes_routing_table = get_routing_table()
            assert fake_ip in multiple_routes_routing_table, f'{fake_ip} does not exist in the routing table (multiple)'
            assert fake_ip_2 in multiple_routes_routing_table, f'{fake_ip_2} does not exist in the routing table (multiple)'

            # Now, remove one of them, and ensure that is is reinstalled by agent
            os.system(f'ip route del {fake_ip_2}')
            wait(resolution_interval)
            updated_routes = get_routing_table()
            assert fake_ip_2 in updated_routes, f'{fake_ip_2} does not exist in the routing table (multiple) after manually removal'

            # Install the route with the fake domain
            (ok, err_str) = agent.cli(f'-f {cli_file_fqdn_routes_remove}')
            assert ok, err_str
            wait(resolution_interval)
            routing_table_after_removal = get_routing_table()
            assert routing_table_after_removal == start_routing_table, 'routing table should not contain the fqdn route after remove-route'
        finally:
            # restore the original /etc/hosts file
            os.system('cp /etc/hosts.orig /etc/hosts')
            os.system('rm /etc/hosts.orig')

if __name__ == '__main__':
    test()
