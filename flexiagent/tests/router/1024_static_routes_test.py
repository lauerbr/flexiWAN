################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
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
import subprocess
import sys
import time

code_root = os.path.realpath(__file__).replace('\\','/').split('/tests/')[0]
test_root = code_root + '/tests/'
sys.path.append(test_root)
import fwtests

def flow_01(fixture_globals=None):
    with fwtests.TestFwagent() as agent:
        tests_path = __file__.replace('.py', '')
        test_cases = sorted(glob.glob('%s/*.cli' % tests_path))

        print("")
        for (idx,t) in enumerate(test_cases):

            print("   " + os.path.basename(t))

            daemon = True if idx == 0 else False
            (ok,_) = agent.cli(f'-f {t}', daemon=daemon)
            assert ok, f"{t} failed"

            if idx == 0:
                # Ensure multi-hop static route worked OK (after the first CLI).
                # After the 01_.*cli following routes are expected:
                #   default via 10.0.0.10 dev vpp1 proto static
                #   default via 192.168.1.1 dev enp0s3 proto dhcp src 192.168.1.208 metric 100
                #   1.1.1.0/24 via 10.0.0.10 dev vpp1 proto static
                #   1.1.1.0/24 proto static metric 300
                #             nexthop via 192.168.56.102 dev vpp2 weight 1
                #             nexthop via 10.0.0.10 dev vpp1 weight 1
                #   10.0.0.0/24 dev vpp1 proto kernel scope link src 10.0.0.4
                #   192.168.1.0/24 dev enp0s3 proto kernel scope link src 192.168.1.208
                #   192.168.1.1 dev enp0s3 proto dhcp scope link src 192.168.1.208 metric 100
                #   192.168.56.0/24 dev enp0s10 proto kernel scope link src 192.168.56.171
                #   192.168.56.0/24 dev vpp2 proto kernel scope link src 192.168.56.101
                #
                cmd = 'sleep 2 && (ip r | grep "1.1.1.0/24 proto static metric 300" -A 2 | grep nexthop | wc -l)'
                out = subprocess.check_output(cmd, shell=True).decode().strip()
                assert out=="2", "multi-hop route with two hops was not found"

def flow_02():
    '''This tests ensures that if user added route to both Linux and to device
    configuration, then start-router will not fail due to add-route failure.
    Actually, the implementation just do not fails 'add-route' in this case.
    Just ignores it.
    '''
    tests_path = __file__.replace('.py', '')
    with fwtests.TestFwagent() as agent:

        (ok,_) = agent.cli(f'-f {tests_path}/01_start-router_add-route.cli', daemon=True)
        assert ok, f"01_start-router_add-route.cli failed"

        route, via = "9.9.9.9/32", agent.get_template_parameter("__INTERFACE_1__gateway")
        linux_add_route = f"ip route add {route} via {via} proto static"
        agent_add_route = {
                        "message": "add-route",
                        "params": {
                            "addr": route,
                            "via":  via
                        }
                    }

        subprocess.call(linux_add_route, shell=True)
        time.sleep(1)

        reply = agent.inject_requests(agent_add_route)
        assert bool(reply.get("ok")), f"injected request failed: request={agent_add_route}, reply={reply}"

def test():
    print("")
    print("    flow_01")
    flow_01()
    print("    flow_02")
    flow_02()

if __name__ == '__main__':
    test()
