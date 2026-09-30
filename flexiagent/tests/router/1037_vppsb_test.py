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
sys.path.append(code_root)
sys.path.append(test_root)
import fwtests
import fwutils

cli_path = __file__.replace('.py', '')
cli_file_initial_cfg = os.path.join(cli_path, 'initial_cfg.cli')

def validate_routes(agent):
    '''This routine tests VPPSB faultlessness with regard to routes.
    It creates following routes in kernel:
        6.6.6.0/24 via 192.168.1.1 dev vpp1 proto dhcp metric 200
        6.6.6.0/24 via 192.168.1.1 dev vpp1 proto bgp  metric 210
        6.6.6.0/24 via 192.168.1.1 dev vpp1 proto ospf metric 220
    and ensures that:
        1. VPPSB has all of them with FIB refCounter 3:
            root@vbox-171:~# vppctl sh tap-inject routes | grep 6.6.6.0
            [28]: 6.6.6.0/24 via 192.168.1.1 oif 13 table 254 priority 200 fib_ref_counter 3 (idx=0)
            [29]: 6.6.6.0/24 via 192.168.1.1 oif 13 table 254 priority 210 fib_ref_counter 3 (idx=0)
            [30]: 6.6.6.0/24 via 192.168.1.1 oif 13 table 254 priority 220 fib_ref_counter 3 (idx=0)
            root@vbox-171:~# vppctl sh tap-inject routes | grep -E '6.6.6.0.*ref_counter 3' | wc -l
            3
        2. VPP FIB has only on them
            root@vbox-171:~# vppctl sh fib entry | grep 6.6.6.0
            33@6.6.6.0/24
            root@vbox-171:~# vppctl sh fib entry | grep 6.6.6.0 | wc -l
            1
    Then one route is removed and 2 routes in VPPSB and 1 in FIB are ensured.
    Then all the rest are removed and no routes in VPPSB and in FIB are ensured.
    Then all three are added back and 3 routes in VPPSB and 1 in FIB are ensured.
    '''
    (via, dev, _, _, _) = fwutils.get_default_route(resolve_dev_id=False)
    routes = [
        f"6.6.6.0/24 via {via} dev {dev} proto dhcp metric 200",
        f"6.6.6.0/24 via {via} dev {dev} proto bgp  metric 210",
        f"6.6.6.0/24 via {via} dev {dev} proto ospf metric 220",
    ]

    # Step 01: add 3 routes to kernel and validate 3 routes in VPPSB and 1 in VPP FIB
    #
    for route in routes:
        subprocess.check_call(f"ip route add {route} && sleep 1", shell=True)
    out = subprocess.check_output(f"vppctl sh tap-inject routes | grep -E '6.6.6.0.*ref_counter 3' | wc -l", shell=True).decode().strip()
    assert out=="3", f"VPPSB has {out} routes instead of 3"
    out = subprocess.check_output(f"vppctl sh fib entry | grep 6.6.6.0 | wc -l", shell=True).decode().strip()
    assert out=="1", f"VPP FIB has {out} routes instead of 1"

    # Step 02: remove 1 route from kernel and validate 2 routes in VPPSB and 1 in VPP FIB
    #
    subprocess.check_call(f"ip route del {routes[1]} && sleep 1", shell=True)
    out = subprocess.check_output(f"vppctl sh tap-inject routes | grep -E '6.6.6.0.*ref_counter 2' | wc -l", shell=True).decode().strip()
    assert out=="2", f"VPPSB has {out} routes instead of 2"
    out = subprocess.check_output(f"vppctl sh fib entry | grep 6.6.6.0 | wc -l", shell=True).decode().strip()
    assert out=="1", f"VPP FIB has {out} routes instead of 1"

    # Step 03: remove all the rest routes from kernel and validate 0 routes in VPPSB and 0 in VPP FIB
    #
    subprocess.check_call(f"ip route del {routes[0]} && sleep 1", shell=True)
    subprocess.check_call(f"ip route del {routes[2]} && sleep 1", shell=True)
    out = subprocess.check_output(f"vppctl sh tap-inject routes | grep -E '6.6.6.0' | wc -l", shell=True).decode().strip()
    assert out=="0", f"VPPSB has {out} routes instead of 0"
    out = subprocess.check_output(f"vppctl sh fib entry | grep 6.6.6.0 | wc -l", shell=True).decode().strip()
    assert out=="0", f"VPP FIB has {out} routes instead of 0"

    # Step 04: add back 3 routes to kernel and validate 3 routes in VPPSB and 1 in VPP FIB
    #
    for route in routes:
        subprocess.check_call(f"ip route add {route} && sleep 1", shell=True)
    out = subprocess.check_output(f"vppctl sh tap-inject routes | grep -E '6.6.6.0.*ref_counter 3' | wc -l", shell=True).decode().strip()
    assert out=="3", f"VPPSB has {out} routes instead of 3"
    out = subprocess.check_output(f"vppctl sh fib entry | grep 6.6.6.0 | wc -l", shell=True).decode().strip()
    assert out=="1", f"VPP FIB has {out} routes instead of 1"


def test():
    with fwtests.TestFwagent() as agent:
        (ok, err_str) = agent.cli(f'-f {cli_file_initial_cfg}', daemon=True)
        assert ok, err_str
        validate_routes(agent)

if __name__ == '__main__':
    test()
