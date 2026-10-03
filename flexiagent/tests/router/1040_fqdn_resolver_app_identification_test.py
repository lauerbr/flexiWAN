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
cli_file_add_firewall_policy      = os.path.join(cli_path, 'add_firewall_policy.cli')
cli_file_remove_firewall_policy   = os.path.join(cli_path, 'remove_firewall_policy.cli')
cli_file_add_multilink_policy     = os.path.join(cli_path, 'add_multilink_policy.cli')
cli_file_remove_multilink_policy  = os.path.join(cli_path, 'remove_multilink_policy.cli')

cli_file_add_applications_category     = os.path.join(cli_path, 'add_applications_category.cli')
cli_file_add_multilink_policy_category = os.path.join(cli_path, 'add_multilink_policy_category.cli')

cli_file_add_applications_multiple_fqdn = os.path.join(cli_path, 'add_applications_multiple_fqdn.cli')

fake_domain = 'fakedomainfakedomain.com' # "fakedomain.com" exists in the public DNS servers (:
fake_domain_2 = 'fakedomainfakedomain2.com' # "fakedomain.com" exists in the public DNS servers (:
fake_ip = '9.9.9.9'
fake_ip_2 = '10.10.10.10'
fake_ip_3 = '11.11.11.11'
fake_ip_4 = '12.12.12.12'

def wait(resolution_interval):
    time.sleep(resolution_interval * 1.5)  # wait a bit more than the resolution interval to ensure the route is resolved

def get_vpp_acls(idx=None):
    cmd ='vppctl show acl-plugin acl'
    if idx:
        cmd += f' index {idx}'
    return subprocess.check_output(cmd, shell=True).decode()

def check_applications(resolution_interval):
    # Check that VPP contains two ACLs (one application), with no rules (no resolution at this time)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be created with no rules'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be created with no rules'

    # Add fake ip to the fake domain and ensure that application ACLs get updated
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule'
    assert f'permit src {fake_ip}/32 dst 0.0.0.0/0' in acls, f'{fake_ip}/32 must be permitted as source'
    assert f'permit src 0.0.0.0/0 dst {fake_ip}/32' in acls, f'{fake_ip}/32 must be permitted as destination'

    # Change the fake ip of the fake domain and ensure that application ACLs get updated correctly with the new ip
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule'
    assert f'permit src {fake_ip_2}/32 dst 0.0.0.0/0' in acls, f'{fake_ip_2}/32 must be permitted as source'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_2}/32' in acls, f'{fake_ip_2}/32 must be permitted as destination'

    # Remove the fake IP and keep the domain unresolved, and ensure that ACLs where removed
    os.system("sed -i '$d' /etc/hosts")
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be updated to be with no rules'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be updated to be with no rules'

    # Now, let's check multiple IPs resolved for the fake domain
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 2' in acls, 'acl-index 0 must be created with two rules'
    assert 'acl-index 1 count 2' in acls, 'acl-index 1 must be created with two rules'
    assert f'permit src {fake_ip}/32 dst 0.0.0.0/0' in acls, f'{fake_ip}/32 must be permitted as source (multiple)'
    assert f'permit src 0.0.0.0/0 dst {fake_ip}/32' in acls, f'{fake_ip}/32 must be permitted as destination (multiple)'
    assert f'permit src {fake_ip_2}/32 dst 0.0.0.0/0' in acls, f'{fake_ip_2}/32 must be permitted as source (multiple)'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_2}/32' in acls, f'{fake_ip_2}/32 must be permitted as destination (multiple)'

    # Remove both IPs
    os.system("sed -i '$d' /etc/hosts")
    os.system("sed -i '$d' /etc/hosts")
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be updated to be with no rules (after multiple)'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be updated to be with no rules (after multiple)'

def check_firewall(agent, resolution_interval):
    (ok, err_str) = agent.cli(f'-f {cli_file_add_firewall_policy}')
    assert ok, err_str

    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be created with no rules (app)'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be updated with no rules (app)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 (deny all) must be created (firewall)'
    assert 'permit src 0.0.0.0/0 dst 0.0.0.0/0' in acls, 'acl-index 2 (deny all) must be created (firewall)'
    assert 'acl-index 3 count 0' in acls, 'acl-index 3 must be updated with no rules (firewall)'
    assert 'acl-index 4 count 0' in acls, 'acl-index 4 must be updated with no rules (firewall)'

    # Add fake ip to the fake domain and ensure that application and firewall ACLs get updated
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule (app)'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule (app)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 (deny all) must be created (firewall)'
    assert 'permit src 0.0.0.0/0 dst 0.0.0.0/0' in acls, 'acl-index 2 (deny all) must be created (firewall)'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must contains one rule (firewall)'
    assert 'acl-index 4 count 1' in acls, 'acl-index 4 must contains one rule (firewall)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 2, f'{fake_ip}/32 must be exists twice as source'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 2, f'{fake_ip}/32 must be exists twice as destination'

    # Change the fake ip of the fake domain and ensure that application ACLs get updated correctly with the new ip
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule (app) - after update'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule (app) - after update'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 (deny all) must be created (firewall) - after update'
    assert 'permit src 0.0.0.0/0 dst 0.0.0.0/0' in acls, 'acl-index 2 (deny all) must be created (firewall) - after update'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must contains one rule (firewall) - after update'
    assert 'acl-index 4 count 1' in acls, 'acl-index 4 must contains one rule (firewall) - after update'
    assert acls.count(f'permit src {fake_ip_2}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_2}/32 must be exists twice as source - after update'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_2}/32') == 2, f'{fake_ip_2}/32 must be exists twice as destination - after update'

    # Now, let's check multiple IPs resolved for the fake domain
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 2' in acls, 'acl-index 0 must contains two rules (app) - (multiple) - firewall'
    assert 'acl-index 1 count 2' in acls, 'acl-index 1 must contains two rules (app) - (multiple) - firewall'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 (deny all) must be created (firewall) - (multiple)'
    assert 'permit src 0.0.0.0/0 dst 0.0.0.0/0' in acls, 'acl-index 2 (deny all) must be created (firewall) - (multiple)'
    assert 'acl-index 3 count 2' in acls, 'acl-index 3 must contains two rules (firewall) - (multiple)'
    assert 'acl-index 4 count 2' in acls, 'acl-index 4 must contains two rules (firewall) - (multiple)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 2, f'{fake_ip}/32 must be exists twice as source - (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 2, f'{fake_ip}/32 must be exists twice as destination - (multiple)'
    assert acls.count(f'permit src {fake_ip_2}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_2}/32 must be exists twice as source - (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_2}/32') == 2, f'{fake_ip_2}/32 must be exists twice as destination - (multiple)'

    # Remove both IPs
    os.system("sed -i '$d' /etc/hosts")
    os.system("sed -i '$d' /etc/hosts")
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be updated with no rules (app) - after remove'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be updated with no rules (app) - after remove'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 (deny all) must be created (firewall) - after remove'
    assert 'permit src 0.0.0.0/0 dst 0.0.0.0/0' in acls, 'acl-index 2 (deny all) must be created (firewall) - after remove'
    assert 'acl-index 3 count 0' in acls, 'acl-index 3 must be updated with no rules (firewall) - after remove'
    assert 'acl-index 4 count 0' in acls, 'acl-index 4 must be updated with no rules (firewall) - after remove'

    (ok, err_str) = agent.cli(f'-f {cli_file_remove_firewall_policy}')
    assert ok, err_str

def check_policy_with_category_rule(agent, resolution_interval):
    (ok, err_str) = agent.cli(f'-f {cli_file_add_applications_category}')
    assert ok, err_str

    (ok, err_str) = agent.cli(f'-f {cli_file_add_multilink_policy_category}')
    assert ok, err_str

    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be created with no rules (fqdn app)'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be created with no rules (fqdn app)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 must be created with one rule (non-fqdn app)'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must be created with one rule (non-fqdn app)'
    assert 'acl-index 4 count 2' in acls, 'acl-index 4 must be created with two rules for non-fqdn app (policy)'
    assert acls.count(f'permit src {fake_ip_3}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_3}/32 must be exists twice as source'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_3}/32') == 2, f'{fake_ip_3}/32 must be exists twice as destination'

    # Add fake ip to the fake domain and ensure that application and firewall ACLs get updated
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule (fqdn app)'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule (fqdn app)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 must contains one rule as before (non-fqdn app)'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must contains one rule as before (non-fqdn app)'
    assert 'acl-index 4 count 4' in acls, 'acl-index 4 must contains four rules with two rules for each app (policy)'
    assert acls.count(f'permit src {fake_ip_3}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_3}/32 must be exists twice as source (after resolution)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_3}/32') == 2, f'{fake_ip_3}/32 must be exists twice as destination (after resolution)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 2, f'{fake_ip}/32 must be exists twice as source (after resolution)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 2, f'{fake_ip}/32 must be exists twice as destination (after resolution)'

    # Change the fake ip of the fake domain and ensure that application and policy ACLs get updated correctly with the new ip
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule (fqdn app)'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule (fqdn app)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 must contains one rule as before (non-fqdn app)'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must contains one rule as before (non-fqdn app)'
    assert 'acl-index 4 count 4' in acls, 'acl-index 4 must contains four rules with two rules for each app (policy)'
    assert acls.count(f'permit src {fake_ip_3}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_3}/32 must be exists twice as source (after resolution update)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_3}/32') == 2, f'{fake_ip_3}/32 must be exists twice as destination (after resolution update)'
    assert acls.count(f'permit src {fake_ip_2}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_2}/32 must be exists twice as source (after resolution update)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_2}/32') == 2, f'{fake_ip_2}/32 must be exists twice as destination (after resolution update)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 0, f'{fake_ip}/32 must not be exists twice as source (after resolution update)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 0, f'{fake_ip}/32 must not be exists twice as destination (after resolution update)'

    # Now, let's check multiple IPs resolved for the fake domain
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 2' in acls, 'acl-index 0 must contains two rules (fqdn app) - (multiple)'
    assert 'acl-index 1 count 2' in acls, 'acl-index 1 must contains two rules (fqdn app) - (multiple)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 must contains one rule as before (non-fqdn app) - (multiple)'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must contains one rule as before (non-fqdn app) - (multiple)'
    assert 'acl-index 4 count 6' in acls, 'acl-index 4 must contains 6 rules (policy) - (multiple)'
    assert acls.count(f'permit src {fake_ip_3}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_3}/32 must be exists twice as source (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_3}/32') == 2, f'{fake_ip_3}/32 must be exists twice as destination (multiple)'
    assert acls.count(f'permit src {fake_ip_2}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_2}/32 must be exists twice as source (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_2}/32') == 2, f'{fake_ip_2}/32 must be exists twice as destination (multiple)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 2, f'{fake_ip}/32 must be exists twice as source (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 2, f'{fake_ip}/32 must be exists twice as destination (multiple)'

    # Remove both IPs
    os.system("sed -i '$d' /etc/hosts")
    os.system("sed -i '$d' /etc/hosts")
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be created with no rules (fqdn app) (unresolved)'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be created with no rules (fqdn app) (unresolved)'
    assert 'acl-index 2 count 1' in acls, 'acl-index 2 must be created with one rule (non-fqdn app) (unresolved)'
    assert 'acl-index 3 count 1' in acls, 'acl-index 3 must be created with one rule (non-fqdn app) (unresolved)'
    assert 'acl-index 4 count 2' in acls, 'acl-index 4 must be created with two rules for non-fqdn app (policy) (unresolved)'
    assert acls.count(f'permit src {fake_ip_3}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_3}/32 must be exists twice as source (unresolved)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_3}/32') == 2, f'{fake_ip_3}/32 must be exists twice as destination (unresolved)'

def check_policy_with_fqdn_application(agent, resolution_interval):
    (ok, err_str) = agent.cli(f'-f {cli_file_add_multilink_policy}')
    assert ok, err_str

    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be created with no rules (app)'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be updated with no rules (app)'
    assert 'acl-index 2 count 0' in acls, 'acl-index 2 must be created (policy)'

    # Add fake ip to the fake domain and ensure that application and firewall ACLs get updated
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule (app)'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule (app)'
    assert 'acl-index 2 count 2' in acls, 'acl-index 2 must contains two rules (policy)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 2, f'{fake_ip}/32 must be exists twice as source'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 2, f'{fake_ip}/32 must be exists twice as destination'

    # Change the fake ip of the fake domain and ensure that application and policy ACLs get updated correctly with the new ip
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must contains one rule (app) - after update'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must contains one rule (app) - after update'
    assert 'acl-index 2 count 2' in acls, 'acl-index 2 must contains two rules (policy) - after update'
    assert acls.count(f'permit src {fake_ip_2}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_2}/32 must be exists twice as source - after update'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_2}/32') == 2, f'{fake_ip_2}/32 must be exists twice as destination - after update'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 0, f'old {fake_ip}/32 must be removed - after update'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 0, f'old {fake_ip}/32 must be removed - after update'

    # Now, let's check multiple IPs resolved for the fake domain
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 2' in acls, 'acl-index 0 must contains two rules (app) - (multiple)'
    assert 'acl-index 1 count 2' in acls, 'acl-index 1 must contains two rules (app) - (multiple)'
    assert 'acl-index 2 count 4' in acls, 'acl-index 2 must contains four rules (policy) - (multiple)'
    assert acls.count(f'permit src {fake_ip}/32 dst 0.0.0.0/0') == 2, f'{fake_ip}/32 must be exists twice as source - (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip}/32') == 2, f'{fake_ip}/32 must be exists twice as destination - (multiple)'
    assert acls.count(f'permit src {fake_ip_2}/32 dst 0.0.0.0/0') == 2, f'{fake_ip_2}/32 must be exists twice as source - (multiple)'
    assert acls.count(f'permit src 0.0.0.0/0 dst {fake_ip_2}/32') == 2, f'{fake_ip_2}/32 must be exists twice as destination - (multiple)'

    # Remove both IPs
    os.system("sed -i '$d' /etc/hosts")
    os.system("sed -i '$d' /etc/hosts")
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 0' in acls, 'acl-index 0 must be updated with no rules (app) - after remove'
    assert 'acl-index 1 count 0' in acls, 'acl-index 1 must be updated with no rules (app) - after remove'
    assert 'acl-index 2 count 0' in acls, 'acl-index 2 must be updated with no rules (policy) - after remove'

    (ok, err_str) = agent.cli(f'-f {cli_file_remove_firewall_policy}')
    assert ok, err_str

def check_multilink_policy(agent, resolution_interval):
    # Check that policy rule that based on an FQDN application is getting updated correctly based on resolution
    check_policy_with_fqdn_application(agent, resolution_interval)

    # More complex test that checks policy based on category, and one of the applications in the category is fqdn
    check_policy_with_category_rule(agent, resolution_interval)

    (ok, err_str) = agent.cli(f'-f {cli_file_remove_multilink_policy}')
    assert ok, err_str

def check_multilink_rules(agent, resolution_interval):
    (ok, err_str) = agent.cli(f'-f {cli_file_add_applications_multiple_fqdn}')
    assert ok, err_str

    # only one should be created for the static ip (non-fqdn rule)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must be created with one rule (only static)'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must be created with one rule (only static)'
    assert 'permit src 11.11.11.11/32 dst 0.0.0.0/0 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 0 must be created with static rule'
    assert 'permit src 0.0.0.0/0 dst 11.11.11.11/32 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 1 must be created with static rule'

    # Add fake ip to the fake domain and ensure that the resolved domain is updated in VPP
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 2' in acls, 'acl-index 0 must contains two rules (static and resolved)'
    assert 'acl-index 1 count 2' in acls, 'acl-index 1 must contains two rules (static and resolved)'
    assert 'permit src 11.11.11.11/32 dst 0.0.0.0/0 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 0 must be stayed with static rule'
    assert 'permit src 0.0.0.0/0 dst 11.11.11.11/32 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 1 must be stayed with static rule'
    assert f'permit src {fake_ip}/32 dst 0.0.0.0/0 proto 6 sport 1000-2000 dport 0-65535' in acls, 'acl-index 0 should contains the resolved IP'
    assert f'permit src 0.0.0.0/0 dst {fake_ip}/32 proto 6 sport 0-65535 dport 1000-2000' in acls, 'acl-index 1 should contains the resolved IP'

    # Change the fake ip of the fake domain and ensure that application and policy ACLs get updated correctly with the new ip
    os.system("sed -i '$d' /etc/hosts")
    os.system(f'echo "{fake_ip_2} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 2' in acls, 'acl-index 0 must contains two rules (Static and resolved) - after update'
    assert 'acl-index 1 count 2' in acls, 'acl-index 1 must contains two rules (Static and resolved) - after update'
    assert 'permit src 11.11.11.11/32 dst 0.0.0.0/0 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 0 must be stayed with static rule - after update'
    assert 'permit src 0.0.0.0/0 dst 11.11.11.11/32 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 1 must be stayed with static rule - after update'
    assert f'permit src {fake_ip_2}/32 dst 0.0.0.0/0 proto 6 sport 1000-2000 dport 0-65535' in acls, 'acl-index 0 should contains the resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_2}/32 proto 6 sport 0-65535 dport 1000-2000' in acls, 'acl-index 1 should contains the resolved IP - after update'

    # now resolve the second rule
    os.system(f'echo "{fake_ip_4} {fake_domain_2}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 4' in acls, 'acl-index 0 must contains 4 rules (Static and two resolved)'
    assert 'acl-index 1 count 4' in acls, 'acl-index 1 must contains 4 rules (Static and two resolved)'
    assert 'permit src 11.11.11.11/32 dst 0.0.0.0/0 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 0 must be stayed with static rule - after update'
    assert 'permit src 0.0.0.0/0 dst 11.11.11.11/32 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 1 must be stayed with static rule - after update'
    assert f'permit src {fake_ip_2}/32 dst 0.0.0.0/0 proto 6 sport 1000-2000 dport 0-65535' in acls, 'acl-index 0 should contains the resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_2}/32 proto 6 sport 0-65535 dport 1000-2000' in acls, 'acl-index 1 should contains the resolved IP - after update'
    assert f'permit src {fake_ip_4}/32 dst 0.0.0.0/0 proto 17 sport 3000-4000 dport 0-65535' in acls, 'acl-index 0 should contains the second resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_4}/32 proto 17 sport 0-65535 dport 3000-4000' in acls, 'acl-index 1 should contains the second resolved IP - after update'
    assert f'permit src {fake_ip_4}/32 dst 0.0.0.0/0 proto 6 sport 3000-4000 dport 0-65535' in acls, 'acl-index 0 should contains the second resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_4}/32 proto 6 sport 0-65535 dport 3000-4000' in acls, 'acl-index 1 should contains the second resolved IP - after update'

    # now add second IP to the first resolved domain
    os.system(f'echo "{fake_ip} {fake_domain}" >> /etc/hosts')
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 5' in acls, 'acl-index 0 must contains 5 rules (Static and two resolved - one with multiple)'
    assert 'acl-index 1 count 5' in acls, 'acl-index 1 must contains 5 rules (Static and two resolved - one with multiple)'
    assert 'permit src 11.11.11.11/32 dst 0.0.0.0/0 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 0 must be stayed with static rule - after update'
    assert 'permit src 0.0.0.0/0 dst 11.11.11.11/32 proto 0 sport 0-65535 dport 0-65535' in acls, 'acl-index 1 must be stayed with static rule - after update'
    assert f'permit src {fake_ip_2}/32 dst 0.0.0.0/0 proto 6 sport 1000-2000 dport 0-65535' in acls, 'acl-index 0 should contains the resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_2}/32 proto 6 sport 0-65535 dport 1000-2000' in acls, 'acl-index 1 should contains the resolved IP - after update'
    assert f'permit src {fake_ip}/32 dst 0.0.0.0/0 proto 6 sport 1000-2000 dport 0-65535' in acls, 'acl-index 0 should contains the resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip}/32 proto 6 sport 0-65535 dport 1000-2000' in acls, 'acl-index 1 should contains the resolved IP - after update'
    assert f'permit src {fake_ip_4}/32 dst 0.0.0.0/0 proto 17 sport 3000-4000 dport 0-65535' in acls, 'acl-index 0 should contains the second resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_4}/32 proto 17 sport 0-65535 dport 3000-4000' in acls, 'acl-index 1 should contains the second resolved IP - after update'
    assert f'permit src {fake_ip_4}/32 dst 0.0.0.0/0 proto 6 sport 3000-4000 dport 0-65535' in acls, 'acl-index 0 should contains the second resolved IP - after update'
    assert f'permit src 0.0.0.0/0 dst {fake_ip_4}/32 proto 6 sport 0-65535 dport 3000-4000' in acls, 'acl-index 1 should contains the second resolved IP - after update'

    # now clean all
    os.system("sed -i '$d' /etc/hosts")
    os.system("sed -i '$d' /etc/hosts")
    os.system("sed -i '$d' /etc/hosts")
    wait(resolution_interval)
    acls = get_vpp_acls()
    assert 'acl-index 0 count 1' in acls, 'acl-index 0 must be created with one rule (only static) - after removal'
    assert 'acl-index 1 count 1' in acls, 'acl-index 1 must be created with one rule (only static) - after removal'

def test(fqdn_fast_resolution):
    resolution_interval = fqdn_fast_resolution[0]
    agent_conf_filename = fqdn_fast_resolution[1]
    with fwtests.TestFwagent() as agent:
        try:
            # take a copy of the /etc/hosts file
            os.system('cp /etc/hosts /etc/hosts.orig')

            # inject start router and add-application with FQDN application (unresolved)
            (ok, err_str) = agent.cli(f'-f {cli_file_initial_cfg}', daemon=True, agent_conf_filename=agent_conf_filename)
            assert ok, err_str

            wait(resolution_interval)

            # Check FQDN resolution impact on applications
            check_applications(resolution_interval)

            # Check FQDN resolution impact on firewall
            check_firewall(agent, resolution_interval)

            # Check FQDN resolution impact on multilink policy
            check_multilink_policy(agent, resolution_interval)

            # Check multiple FQDN rules
            check_multilink_rules(agent, resolution_interval)

        finally:
            # restore the original /etc/hosts file
            os.system('cp /etc/hosts.orig /etc/hosts')
            os.system('rm /etc/hosts.orig')

if __name__ == '__main__':
    test()
