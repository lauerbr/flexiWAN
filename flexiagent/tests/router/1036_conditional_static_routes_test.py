################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2023  flexiWAN Ltd.
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
sys.path.append(test_root)
import fwtests

cli_path = __file__.replace('.py', '')
cli_file_conditional_routes_add     = os.path.join(cli_path, 'conditional_routes_add.cli')
cli_file_initial_cfg                = os.path.join(cli_path, 'initial_cfg.cli')
cli_file_remove_devices             = os.path.join(cli_path, 'remove_devices.cli')
cli_file_trigger_routes_add         = os.path.join(cli_path, 'trigger_routes_add.cli')
cli_file_trigger_routes_remove      = os.path.join(cli_path, 'trigger_routes_remove.cli')

################################################################################
# This test validates the Conditional Static Route functionality of flexiEdge agent.
# It configures agent with trigger and with conditional routes and ensures
# that conditional routes react properly to adding and to removal of trigger routes.
# Trigger routes reflect conditions apparently.
#
# Please see below an example of CSR add-route request:
#            {
#                "entity": "agent",
#                "message": "add-route",
#                "params": {
#                    "addr":   "172.16.1.0/24",
#                    "via":    "10.65.205.130",
#                    "dev_id": "pci:0000:00:08.0",
#                    "condition": {
#                        "type": "route-not-exist",     // route to 10.0.0.0/24 via tunnel 3 does not exist
#                        "addr": "10.0.0.0/24",         // can be a specific address, e.g. 10.0.0.138
#                        "dev":  { "tunnel-id": "3" }   // can be  { "dev_id": "pci:0000:00:03.0" } for LAN/WAN
#                    }
#                }
#            }
#
#    Initial config:
#    -------------------------------------------------------------
#    i1  - add-interface WAN-1
#    i1  - add-interface LAN-2
#    i1  - add-interface LAN-3
#    t1  - add-tunnel 1 via WAN-1
#
#    Trigger Routes
#    -------------------------------------------------------------
#    tr1 - add-route { 1.1.1.1/32 via LAN-3}
#    tr2 - add-route { 2.2.2.0/24 via LAN-3}
#    tr3 - add-route { 3.3.3.3/32 via Tunnel-1}
#    tr4 - add-route { 4.4.4.0/24 via Tunnel-1}
#
#    Conditional Routes (to be tested)
#    -------------------------------------------------------------
#    cr1 - add-route { 100.100.100.101/32 via LAN-2 condition ROUTE-EXIST     1.1.1.1 via LAN-3}
#    cr2 - add-route { 100.100.100.102/32 via LAN-2 condition ROUTE-EXIST     2.2.2.2 via LAN-3}
#    cr3 - add-route { 100.100.200.103/32 via LAN-2 condition ROUTE-EXIST     3.3.3.3 via Tunnel-1}
#    cr4 - add-route { 100.100.200.104/32 via LAN-2 condition ROUTE-EXIST     4.4.4.4 via Tunnel-1}
#    cr5 - add-route { 100.100.200.101/32 via LAN-2 condition ROUTE-NOT-EXIST 1.1.1.1 via LAN-3}
#    cr6 - add-route { 100.100.200.102/32 via LAN-2 condition ROUTE-NOT-EXIST 2.2.2.2 via LAN-3}
#    cr7 - add-route { 100.100.200.103/32 via LAN-2 condition ROUTE-NOT-EXIST 3.3.3.3 via Tunnel-1}
#    cr8 - add-route { 100.100.200.104/32 via LAN-2 condition ROUTE-NOT-EXIST 4.4.4.4 via Tunnel-1}
#
#    Step-1: add triggers tr1, tr2, tr3, tr4, add cr-s cr1, cr2, cr3, cr4, cr5, cr6:
#            ensure cr1-cr4 exist in Linux and cr5-8 do not exist
#
#    Step-2: remove triggers tr1, tr2, tr3, tr4
#            ensure cr1-cr4 do not exist in Linux and cr5-8 exist
#
#    Step-3: add triggers tr1, tr2, tr3, tr4 back (by add-route):
#            Same results as in Step-1
#
#    Step-4: remove LAN-3 and tunnel-1:
#            3a, 3b - same results as in last step (Step-3) and
#                     errors in log "failed to resolve device name"
#
# NOTE! This test does not validate condition for ROUTE-EXIST via tunnel,
#       as there is no remote end of the tunnel created by this test, and agent
#       silently ignores static routes for tunnels in DOWN state.
################################################################################

CSRs_when_triggers_added = {
    #<route destination>: <expected state>
    "100.100.100.101": "exist",          # condition ROUTE-EXIST     1.1.1.1 via LAN-3
    "100.100.100.102": "exist",          # condition ROUTE-EXIST     2.2.2.2 via LAN-3
    "100.100.100.103": "not-exist",      # condition ROUTE-EXIST     3.3.3.3 via Tunnel-1 - tunnel with no remote end -> route is discarded by agent
    "100.100.100.104": "not-exist",      # condition ROUTE-EXIST     4.4.4.4 via Tunnel-1 - tunnel with no remote end -> route is discarded by agent
    "100.100.200.101": "not-exist",      # condition ROUTE-NOT-EXIST 1.1.1.1 via LAN-3
    "100.100.200.102": "not-exist",      # condition ROUTE-NOT-EXIST 2.2.2.2 via LAN-3
    "100.100.200.103": "exist",          # condition ROUTE-NOT-EXIST 3.3.3.3 via Tunnel-1 - tunnel with no remote end -> route is discarded by agent
    "100.100.200.104": "exist",          # condition ROUTE-NOT-EXIST 4.4.4.4 via Tunnel-1 - tunnel with no remote end -> route is discarded by agent
}

CSRs_when_triggers_removed = {
    #<route destination>: <expected state>
    "100.100.100.101": "not-exist",      # condition ROUTE-EXIST     1.1.1.1 via LAN-3
    "100.100.100.102": "not-exist",      # condition ROUTE-EXIST     2.2.2.2 via LAN-3
    "100.100.100.103": "not-exist",      # condition ROUTE-EXIST     3.3.3.3 via Tunnel-1 - tunnel with no remote end -> route is ignored by agent
    "100.100.100.104": "not-exist",      # condition ROUTE-EXIST     4.4.4.4 via Tunnel-1 - tunnel with no remote end -> route is ignored by agent
    "100.100.200.101": "exist",          # condition ROUTE-NOT-EXIST 1.1.1.1 via LAN-3
    "100.100.200.102": "exist",          # condition ROUTE-NOT-EXIST 2.2.2.2 via LAN-3
    "100.100.200.103": "exist",          # condition ROUTE-NOT-EXIST 3.3.3.3 via Tunnel-1 - tunnel with no remote end -> route is ignored by agent
    "100.100.200.104": "exist",          # condition ROUTE-NOT-EXIST 4.4.4.4 via Tunnel-1 - tunnel with no remote end -> route is ignored by agent
}

def check_routes_in_linux(CSRs):
    time.sleep(8)  # give time to CSR monitoring thread to detect change, it checks condition every 5 seconds

    ok, err = True, []
    for route_dst, expected_state in CSRs.items():
        try:
            subprocess.check_call(f"ip r | grep -E '^{route_dst}' > /dev/null 2>&1", shell=True)
            state = "exist"
        except:
            state = "not-exist"

        if (state != expected_state):
            ok = False
            err.append(f"CSR {route_dst}: {state}, expected: {expected_state}")

    return ok, " ; ".join(err)

def step_01_add_triggers_and_conditional_routes(agent):
    (ok, err_str) = agent.cli(f'-f {cli_file_trigger_routes_add}')
    assert ok, err_str
    (ok, err_str) = agent.cli(f'-f {cli_file_conditional_routes_add}')
    assert ok, err_str
    (ok, err_str) = check_routes_in_linux(CSRs_when_triggers_added)
    assert ok, err_str


def step_02_remove_triggers(agent):
    (ok, err_str) = agent.cli(f'-f {cli_file_trigger_routes_remove}')
    assert ok, err_str
    (ok, err_str) = check_routes_in_linux(CSRs_when_triggers_removed)
    assert ok, err_str


def step_03_add_triggers_back(agent):
    (ok, err_str) = agent.cli(f'-f {cli_file_trigger_routes_add}')
    assert ok, err_str
    (ok, err_str) = check_routes_in_linux(CSRs_when_triggers_added)
    assert ok, err_str


def step_04_remove_devices(agent):
    (ok, err_str) = agent.cli(f'-f {cli_file_remove_devices}')
    assert ok, err_str

    time.sleep(5)  # give time to CSR monitoring thread to detect change

    lines = agent.grep_log('FwConditionalRoute: check: device not found', print_findings=False)
    assert len(lines) >= 6, "log has no mention of 'device not found'"


def test():
    with fwtests.TestFwagent() as agent:

        (ok, err_str) = agent.cli(f'-f {cli_file_initial_cfg}', daemon=True)
        assert ok, err_str

        print("")
        print("    step_01_add_triggers_and_conditional_routes")
        step_01_add_triggers_and_conditional_routes(agent)
        print("    step_02_remove_triggers")
        step_02_remove_triggers(agent)
        print("    step_03_add_triggers_back")
        step_03_add_triggers_back(agent)
        print("    step_04_remove_devices")
        step_04_remove_devices(agent)

if __name__ == '__main__':
    test()
