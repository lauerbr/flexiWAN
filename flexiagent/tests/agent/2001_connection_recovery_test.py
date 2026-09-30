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

import glob
import os
import pytest
import shutil
import subprocess
import sys
import yaml

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
test_name = os.path.realpath(__file__)
test_dir  = __file__.replace('.py', '')
sys.path.append(code_root)
sys.path.append(test_root)
import fwglobals
import fwtests
import fwutils

debug_conf_file = os.path.abspath(test_dir + '/debug_conf.yaml')

cli_start_router_file = os.path.join(test_dir, 'start-router.cli')


def netplan_recovery(agent):

    # Collect current yaml-s to be used for restore on exception
    yamls = {}
    for filepath in glob.glob("/etc/netplan/*.yaml"):
        yamls.update({filepath: f"{filepath}.fwtest"})

    # Generate bad yaml that should test the netplan recovery feature
    spoiled_yaml      = '/etc/netplan/fwtest.spoiled.yaml'
    spoiled_yaml_dict = {
        'network': {
            'renderer': 'networkd',
            'ethernets': {}
        }
    }
    for dev in fwutils.get_kernel_interfaces().values():
        if dev in fwglobals.g.cfg.debug['network']['debugger_interface']['ethernets']:
            continue    # skip debugging interfaces found in debug_conf.yaml
        spoiled_yaml_dict['network']['ethernets'].update({ dev: {"dhcp4": False} })

    # Start test - spoil yamls and ensure the agent is recovered
    try:
        fwglobals.log.debug(f"{test_name}: netplan recovery: start", to_terminal=False)

        for orig_yaml, backup_yaml in yamls.items():
            shutil.move(orig_yaml, backup_yaml)
        with open(spoiled_yaml, 'w', encoding="utf-8") as fd:
            yaml.dump(spoiled_yaml_dict, fd)

        fwutils.netplan_apply(f"{test_name}: netplan recovery: started")

        connection_timeout = 200   # Limit on waiting WebSocket/TCP stack to detect no network and close connection

        agent.set_log_start_marker()

        found = agent.wait_log_line("retry connection in", timeout=connection_timeout)
        assert found, "connection was not broken as a result of spoiling netplan"

        exists = fwutils.call_func_with_retrials(os.path.exists, kargs=[fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE], retrials=connection_timeout)
        assert exists, f"the recovery netplan was not activated: {fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE} not found"

        exists = glob.glob(f"{spoiled_yaml}{fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT}")
        assert exists, f"the bad netplan file {spoiled_yaml} was not marked with '{fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT}'"

        found = agent.wait_log_line("connected to flexiManage", timeout=connection_timeout)
        assert found, "still not connected after netplan recovery"

    except Exception as e:
        raise e
    finally:
        fwglobals.log.debug(f"{test_name}: netplan recovery: finalize", to_terminal=False)
        fwutils.os_remove_files(fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE)
        fwutils.os_remove_files(f'/etc/netplan/*{fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT}')
        fwutils.os_remove_files(spoiled_yaml)
        for orig_yaml, backup_yaml in yamls.items():
            if os.path.exists(backup_yaml):
                shutil.move(backup_yaml, orig_yaml)
        fwutils.netplan_apply(f"{test_name}: netplan recovery: finished")


def router_cfg_change_recovery(agent):

    (ok, _) = agent.cli(f'-f {cli_start_router_file}', set_log_start_marker=True)
    assert ok, f"failed to inject {cli_start_router_file}"

    found = agent.wait_log_line("connected to flexiManage", timeout=90)
    assert found, "agent is not connected to flexiManage after vRouter start"

    # Start test - break connectivity by removal all default routes.
    # The recovery should start as injected above cli_start_router_file is considered
    # to be a configuration change! And it happened in less than WATCHDOG_ROUTER_CFG_WINDOW.
    #
    cmd = 'ip route show default'
    default_route = subprocess.check_output(cmd, shell=True).decode().strip()
    cmd = 'ip route del ' + default_route
    subprocess.check_call(cmd, shell=True)
    fwglobals.log.debug(f'{cmd}: succeeded', to_terminal=False)

    found = agent.wait_log_line("failed to connect", timeout=220) # > WATCHDOG_ROUTER_CFG_WINDOW
    assert found, "connection was not lost"

    found = agent.wait_log_line("FwRecoveryState.IDLE -> FwRecoveryState.IN_PROGRESS")
    assert found, "recovery was not started"

    found = agent.wait_log_line("connected to flexiManage", timeout=60)
    assert found, "connection was not restored"

    found = agent.wait_log_line("FwRecoveryState.IN_PROGRESS -> FwRecoveryState.IDLE")
    assert found, "recovery was not finished"


def test():
    fwglobals.initialize(debug_conf_file=debug_conf_file)  # DO THIS INSIDE test() AND NOT IN GLOBAL SCOPE, so pytest will run it!

    with fwtests.TestFwagent() as agent:
        agent.run_as_daemon(standalone=False, debug_conf_file=debug_conf_file)
        found = agent.wait_log_line("connected to flexiManage")
        if not found:
            pytest.skip('device is not connected to flexiManage')
            return  # we run on device which is not registered and not connected probably

        print("")
        print("    netplan_recovery")
        netplan_recovery(agent)
        print("    router_cfg_change_recovery")
        router_cfg_change_recovery(agent)

    fwglobals.finalize()

if __name__ == '__main__':
    test()
