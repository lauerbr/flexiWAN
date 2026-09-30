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

import re
import socket
import subprocess
import time
import traceback

import fw_input_validation
import fwglobals
import fwpppoe
import fwthread
import fwtunnel_stats
import fwutils

from fwcfg_request_handler import FwCfgMultiOpsWithRevert
from fwobject import FwObject
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError

routes_protocol_map = {
    -1: '',
    0: 'unspec',
    1: 'redirect',
    2: 'kernel',
    3: 'boot',
    4: 'static',
    8: 'gated',
    9: 'ra',
    10: 'mrt',
    11: 'zebra',
    12: 'bird',
    13: 'dnrouted',
    14: 'xorp',
    15: 'ntk',
    16: 'dhcp',
    18: 'keepalived',
    42: 'babel',
    186: 'bgp',
    187: 'isis',
    188: 'ospf',
    189: 'rip',
    192: 'eigrp',
    196: 'zstatic', #RTPROT_ZSTATIC - Null0 route added via FRR-Zebra for LAN SNAT address
}

FRR_NULL_INTERFACE = 'Null0' #Interface name specified in FRR command to add a Null route

routes_protocol_id_map = { y:x for x, y in routes_protocol_map.items() }

class FwRouteKey(str):
    """Route key"""
    def __new__(cls, metric, addr, via):
        obj = f'{addr} {via} {str(metric)}'
        return obj

class FwRouteNextHop:
    """Class used as a route nexthop."""
    def __init__(self, via, dev):
        self.dev        = dev
        self.via        = via

class FwRoute(FwObject):
    """Class used as a route data."""
    def __init__(self, prefix, via, dev, proto, metric, dev_id=None, on_link=False):
        FwObject.__init__(self)
        self.key        = FwRouteKey(metric, prefix, via)
        self.prefix     = prefix
        self.via        = via
        self.dev        = dev
        self.proto      = proto
        self.metric     = metric
        self.dev_id     = dev_id if dev_id else fwutils.get_interface_dev_id(dev)
        self.on_link    = on_link

    def __str__(self):
        route = self.prefix
        if self.via:
            route += f' via {self.via}'
        if self.dev:
            route += f' dev {self.dev} ({self.dev_id})'
        if self.proto:
            route += (' proto ' + str(self.proto))
        if self.metric:
            route += (' metric ' + str(self.metric))
        if self.on_link:
            route += ' on-link'
        return route

    def _install(self):
        (success, err_str) = add_remove_route(
                            self.prefix, self.via, self.metric, remove=False,
                            dev_id=self.dev_id, proto=self.proto, dev=self.dev,
                            on_link=self.on_link)
        err_str = None if success else err_str
        return err_str

    def _uninstall(self):
        try:
            with IPRoute() as ipr:
                ipr.route("del", dst=self.prefix, priority=self.metric)
            err_str = None
        except Exception as e:
            err_str = str(e)
        return err_str

    def _is_installed(self, linux_routes=None):
        if not linux_routes:
            linux_routes = FwLinuxRoutes(prefix=self.prefix, preference=self.metric, proto=self.proto)
        return linux_routes.exist(self.prefix, self.metric, self.via)

    def install(self, check_if_installed=True):
        """Installs route into Linux.
        """
        if check_if_installed and self._is_installed():
            self.log.debug(f"install({self}): exists")
            return
        err_str = self._install()
        if err_str:
            self.log.error(f"install({self}): {err_str}")
        else:
            self.log.debug(f"install({self}): succeeded")

    def uninstall(self, check_if_installed=True):
        """Removes route from Linux.
        """
        if check_if_installed and not self._is_installed():
            self.log.debug(f"uninstall({self}): does not exists")
            return
        err_str = self._uninstall()
        if err_str:
            self.log.error(f"uninstall({self}): {err_str}")
        else:
            self.log.debug(f"uninstall({self}): succeeded")

    def update(self, new_metric):
        """Updates route parameters like metric in Linux.
        """
        err_str = self._uninstall()
        if err_str:
            self.log.error(f"update(metric={new_metric}): failed to uninstall route with old metric: {err_str}: {self}")
            return False

        old_metric , self.metric = self.metric , new_metric
        err_str = self._install()
        if err_str:
            self.log.error(f"update(metric={new_metric}): failed to install route with new metric: {err_str}: {self}")
            self.metric = old_metric
            return False
        return True

    def verify(self, linux_routes, tunnels=None):
        """Verifies that the route is installed in Linux. If it is not, this method installs it.
        In addition, checks if the route is installed in Linux, and it goes via tunnel that is down,
        this method uninstall the route from Linux to prevent routing packets into dead tunnel.
        """
        if not tunnels:
            tunnels = fwtunnel_stats.get_tunnel_info()

        exist_in_linux = linux_routes.exist(self.prefix, self.metric, self.via)
        tunnel_is_down = tunnels.get(self.via) == 'down'

        if exist_in_linux and tunnel_is_down:
            self.log.debug(f"verify: remove route through the broken tunnel: {self}")
            self._uninstall()

        if not exist_in_linux and not tunnel_is_down:
            self.log.debug(f"verify: restore static route: {self}")
            self._install()


class FwConditionalRoute(FwRoute):
    """Implements Static Conditional Route (SCR) abstraction.
    The SCR object provides a number of API-s that enable user to install route
    in system if conditions are satisfied, and to remove route from system,
    if conditions are not satisfied.
    The SCR reflects the 'add-route' configuration request with 'condition' field, e.g:
            {
                "entity": "agent",
                "message": "add-route",
                "params": {
                    "addr":   "172.16.1.0/24",
                    "via":    "10.65.205.130",
                    "dev_id": "pci:0000:00:08.0",
                    "condition": {
                        "type": "route-not-exist",     // route to 10.0.0.0/24 via tunnel 3 does not exist
                        "addr": "10.0.0.0/24",         // can be a specific address, e.g. 10.0.0.138
                        "via":  { "tunnel-id": "3" }   // can be  { "dev_id": "pci:0000:00:03.0" } for LAN/WAN
                    }
                }
            }
    In this example route to "172.16.1.0/24" will be installed only if route to "10.0.0.2/24" via loopback interface
    of the tunnel 3 (e.g. loop4) does not exist. And it will be removed, if route does exist.
    To install/remove route we just run 'ip route add/del 172.16.1.0/24 via 10.65.205.130 dev vpp2' command.
    To check if route in condition exists we check both Linux kernel and FRR database. The FRR should be checked,
    as it holds all available routes, even if they are not optimal and as a result of being not optimal, they are
    not installed in kernel.

    An example of complex condition can be found below:
        {
            "entity": "agent",
            "message": "add-route",
            "params": {
                "addr":   "172.16.1.0/24",
                "via":    "10.65.205.130",
                "dev_id": "pci:0000:00:08.0",
                "condition": {
                    "AND": [
                    {
                        "type": "route-not-exist",
                        "addr": "172.16.1.0/24",
                        "via":  { "tunnel-id": "3" }
                    },
                    {
                        "OR": [
                            {
                                "type": "route-exist",
                                "addr": "192.168.1.0/24",
                                "via":  { "dev_id": "pci:0000:00:03.0" }
                            },
                            {
                                "type": "route-not-exist",
                                "addr": "10.72.100.0/24",
                                "via":  { "dev_id": "pci:0000:00:08.0" }
                            },
                        ]
                    }
                    ]
                }
            }
        }
    """
    def __init__(self, condition, prefix, via, dev, proto, metric, on_link=False, dev_id=None):
        FwRoute.__init__(self, prefix, via, dev, proto, metric, dev_id=dev_id, on_link=on_link)
        self.condition  = condition

    def __str__(self):
        route = FwRoute.__str__(self) + f' condition: {self.condition}'
        return route

    def _check_condition(self, linux_routes):
        if "AND" in self.condition or "OR" in self.condition:
            raise Exception("complex condition is not supported")

        dev_name = None
        if 'tunnel-id' in self.condition['via']:
            dev_name = fwutils.tunnel_to_tap(self.condition['via']['tunnel-id'])
        else:
            dev_name = fwutils.dev_id_to_tap(self.condition['via']['dev_id'])
        if not dev_name:
            raise Exception(f"device not found ({self.condition['via']})")

        route_exist = linux_routes.exist(self.condition['addr'], dev=dev_name)
        if not route_exist:
            # If route was not found in Linux - search in FRR, as FRR keeps all routes, including not optimal ones
            route_exist = fwglobals.g.router_api.frr.get_routes_json(
                                self.condition['addr'], dev=dev_name, ignore_default_routes=True)

        route_status = "route-exist" if route_exist else "route-not-exist"
        result = "satisfied" if self.condition['type'] == route_status else "not satisfied"
        return result

    def verify(self, linux_routes=None, tunnels=None):
        '''Checks the route condition and install/uninstall the route in Linux according the check result.
        '''
        try:
            if not linux_routes:
                linux_routes = FwLinuxRoutes()

            if self._check_condition(linux_routes) == "satisfied":
                FwRoute.verify(self, linux_routes, tunnels)  # verify() installs route if needed
            else:
                if self._is_installed(linux_routes):
                    self.uninstall(check_if_installed=False)
        except Exception as e:
            err_str = f"check: {e}: {self}"
            if not 'device not found' in str(e):
                err_str += f": {traceback.format_exc()}"
            self.log.error(err_str)


def get_default_route():
    via, dev, dev_id, proto, metric = fwutils.get_default_route()
    return FwRoute("0.0.0.0/0", via, dev, proto, metric, dev_id=dev_id)

class FwRoutes(FwObject):
    """Manages all route related activity, e.g. watchdog on sync of static
    routes in router configuration to the actual routes in kernel, or monitor
    of default route change, which might require some actions.
    """
    def __init__(self):
        FwObject.__init__(self)
        self.thread_routes = None
        self.default_route = None
        self.default_iface = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        """Starts the FwRoutes activity - runs the main loop thread.
        """
        self.thread_routes = fwthread.FwRouterThread(target=self.route_thread_func, name="Routes", log=self.log)
        self.thread_routes.start()
        super().initialize()

    def finalize(self):
        """Stops the FwRoutes activity - stops the main loop thread.
        """
        if self.thread_routes:
            self.thread_routes.join()
            self.thread_routes = None
        super().finalize()

    def route_thread_func(self, ticks):
        # Firstly sync static routes from router configuration DB to Linux
        # in order to restore routes that disappeared for some reason,
        # for example due to 'netplan apply' that overrod cfg routes.
        # We do that only if router was started already.
        #
        if fwglobals.g.router_api and fwglobals.g.router_api.state_is_started():
            if ticks % 5 == 0:  # Check routes every ~5 seconds
                self._check_reinstall_static_routes()

        # Check if the default route was modified or if address of the interface
        # used for default route was changed. If it was, reconnect the agent
        # to avoid WebSocket timeout.
        # Note, the get_linux_interfaces() cache is updated by 'netplan apply',
        # which should happen if interface address is modified by user on
        # flexiManage UI.
        #
        if fwglobals.g.fwagent and ticks % 2 == 0:   # every ~2 seconds, it spawns 'ip route'
            self._check_reconnect_on_default_route_change()

    def _check_reinstall_static_routes(self):
        def _get_route_obj(route):
            route_params = {
                'prefix'  : route.get('addr'),
                'via'     : route.get('via'),
                'dev'     : route.get('dev'),
                'proto'   : 'static',
                'metric'  : int(route.get('metric', '0')),
                'on_link' : route.get('onLink', False),
                'dev_id'  : route.get('dev_id')
            }

            condition = route.get('condition')
            if condition:
                route_params['condition'] = condition
                return FwConditionalRoute(**route_params)
            else:
                return FwRoute(**route_params)

        def _get_routes():
            routes = []
            for route in fwglobals.g.router_cfg.get_requests('add-route'):
                addr      = route.get('addr')
                dest_type = route.get('destinationType')

                if dest_type == 'fqdn':
                    addresses = fwglobals.g.fqdn_resolver.get(addr)
                    if not addresses:
                        continue
                    for address in addresses:
                        route_params = dict(route)
                        route_params['addr'] = f'{address}/32'
                        routes.append(_get_route_obj(route_params))
                    continue

                routes.append(_get_route_obj(route))
            return routes

        routes           = _get_routes()
        linux_routes     = FwLinuxRoutes()
        tunnel_addresses = fwtunnel_stats.get_tunnel_info()

        for route in routes:
            route.verify(linux_routes, tunnel_addresses)

    def _check_reconnect_on_default_route_change(self):

        default_route = get_default_route()
        default_iface = fwutils.get_linux_interfaces(if_dev_id=default_route.dev_id)

        # Avoid reconnect on module initialization, it should be done afte
        #
        if default_route == None or default_iface == None:
            self.log.debug(f"_check_reconnect_on_default_route_change: either default_route or default_iface not found")
            return
        if self.default_route == None or self.default_iface == None:
            self.default_route = default_route
            self.default_iface = default_iface
            return

        new_dev, new_via, new_ip = \
            default_route.dev,      default_route.via,      default_iface.get('IPv4')
        old_dev, old_via, old_ip = \
            self.default_route.dev, self.default_route.via, self.default_iface.get('IPv4')

        # To cope with temporary fluctuations of default route caused by 'netplan apply'
        # that might be run for various reasons and that might temporary reset default
        # routes via DHCP interfaces until DHCP renegotiation is finished,
        # we check it few more times to ensure that old default route was not restored.
        #
        for _ in range(3):
            if old_dev == new_dev and old_via == new_via and old_ip == new_ip:
                return   # No change or old default route was restored -> return
            if not new_dev or not new_via or not new_ip:
                return   # No default route is available - reconnection will not help, hope it is temporary due to netplan
            time.sleep(1)
            default_route = get_default_route()
            default_iface = fwutils.get_linux_interfaces(if_dev_id=default_route.dev_id)
            new_dev, new_via, new_ip = \
                default_route.dev, default_route.via, default_iface.get('IPv4')

        if old_dev != new_dev or old_via != new_via:
            self.log.debug(f"reconnect as default route was changed: '{self.default_route}'->'{default_route}'")
        else:
            self.log.debug(f"reconnect as address of {old_dev} was changed: '{old_ip}'->'{new_ip}'")
        fwglobals.g.fwagent.reconnect()
        self.default_route = default_route
        self.default_iface = default_iface

class FwLinuxRoutes(dict):
    """The object that represents routing rules found in OS.
    """
    def __init__(self, prefix=None, preference=None, via=None, proto=None):
        self._linux_get_routes(prefix, preference, via, proto)

    def __getitem__(self, item):
        return self[item]

    def __iadd__(self, src_obj):  # overriding "+=" for "self += src_obj"
        '''Overrides the "+=" operator: adds items from 'src_obj' dict into self.
        If item with same key exists in self, the KeyError exception is thrown.
        If you need different approach, please add dedicated function, e.g. update().
        '''
        for src_key, src_route in src_obj.items():
            if src_key in self:
                raise KeyError(f"key {src_key} exists in destination")
            self[src_key] = src_route
        return self

    def _linux_get_routes(self, prefix=None, preference=None, via=None, proto=None):
        if not proto:
            proto_id = None
        else:
            proto_id = routes_protocol_id_map.get(proto, -1)

        with IPRoute() as ipr:
            try:
                if prefix == '0.0.0.0/0':
                    routes = ipr.get_default_routes(family=socket.AF_INET)
                else:
                    # if we set filter by prefix ipr.get_routes() returns corrupted routes info (incorrect protocol type, priority, etc.)
                    # so we pass only proto instead and filter results by other params like prefix, metric, etc.
                    # routes = ipr.get_routes(dst=prefix, family=socket.AF_INET, proto=proto_id) - returns wrong data
                    routes = ipr.get_routes(family=socket.AF_INET, proto=proto_id)
            except NetlinkError:
                routes = []     # If no matching route exists in kernel, NetlinkError is raised

            # Map interface index into interface name. The links are dumped once
            # on demand for all routes, as dumping them per route is expensive,
            # when there are many routes, e.g. received by BGP.
            #
            link_names = None
            def _get_link_name(index):
                nonlocal link_names
                if link_names is None:
                    link_names = {}
                    try:
                        for link in ipr.get_links():
                            link_names[link['index']] = link.get_attr('IFLA_IFNAME')
                    except NetlinkError:
                        pass
                return link_names.get(index)

            for route in routes:
                nexthops = []
                dst = None # Default routes have no RTA_DST
                metric = 0
                gw = None
                rt_table = 0

                rt_proto = routes_protocol_map[route.get('proto', -1)]

                for attr in route['attrs']:
                    if attr[0] == 'RTA_PRIORITY':
                        metric = int(attr[1])
                    if attr[0] == 'RTA_OIF':
                        if_name = _get_link_name(attr[1])
                        if if_name is None:
                            continue
                        dev = if_name
                    if attr[0] == 'RTA_DST':
                        dst = attr[1]
                    if attr[0] == 'RTA_GATEWAY':
                        gw = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            if_name = _get_link_name(elem['oif'])
                            if if_name is None:
                                continue
                            dev = if_name
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    nexthops.append(FwRouteNextHop(attr2[1],dev))
                    if attr[0] == 'RTA_TABLE':
                        rt_table = int(attr[1])

                if rt_table >= 255:  # ignore bizare routes which are not in main/local tables
                    continue        # See RT_TABLE_X in /usr/include/linux/rtnetlink.h

                if not dst: # Default routes have no RTA_DST
                    dst = "0.0.0.0"
                addr = "%s/%u" % (dst, route['dst_len'])

                if gw:
                    nexthops.append(FwRouteNextHop(gw,dev))

                # check if non None since metric can be 0
                if preference is not None and metric != int(preference):
                    continue

                if prefix and addr != prefix:
                    continue

                if rt_proto == 'zstatic':
                    nexthops.append(FwRouteNextHop(None, FRR_NULL_INTERFACE))
                elif not nexthops:
                    nexthops.append(FwRouteNextHop(None,dev))

                for nexthop in nexthops:
                    if via and via != nexthop.via:
                        continue
                    self[FwRouteKey(metric, addr, nexthop.via)] = FwRoute(addr, nexthop.via, nexthop.dev, rt_proto, metric)

    def exist(self, addr, metric=None, via=None, dev=None):
        route = self.find(addr, metric, via, dev)
        return True if route else False

    def find(self, addr, metric=None, via=None, dev=None):
        if dev:
            for route in dict.values(self):
                if dev==route.dev and addr in route.prefix:  # 'in' takes a care of '/32'
                    return route
            return None

        metric = int(metric) if metric else 0
        key = FwRouteKey(metric, addr, via)
        if key in self:
            return dict.get(self, key)

        # Check if this route exist but with metric changed by WAN_MONITOR
        #
        metric = metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK
        key = FwRouteKey(metric, addr, via)
        if key in self:
            return dict.get(self, key)

        return None

def add_remove_route(addr, via=None, metric=None, remove=False, dev_id=None, proto='static', dev=None, on_link=False, condition=None):
    """Add/Remove route.

    :param addr:            Destination network.
    :param via:             Gateway address.
    :param metric:          Metric.
    :param remove:          True to remove route.
    :param dev_id:          Bus address of device to be used for outgoing packets.
    :param proto:           Route protocol.
    :param dev:             Name of device in Linux to be used for the route.
                            This parameter has higher priority than the 'dev_id'.
    :param on_link:         If True, "onlink" option will be set to the route.
                            It pretends that the 'nexthop' is directly attached to this link, even if it does not match any interface prefix

    :returns: (True, None) tuple on success, (False, <error string>) on failure.
    """
    add    = not remove
    metric = int(metric) if metric else 0

    # The parameters are used in 'ip route' command line, so validate them.
    if addr != 'default' and not fw_input_validation.is_valid_network(addr):
        return (False, f"add_remove_route: invalid address {addr!r}")
    if via and not fw_input_validation.is_valid_ip(via):
        return (False, f"add_remove_route: invalid gateway {via!r}")
    if not fw_input_validation.is_shell_safe_word(str(proto)):
        return (False, f"add_remove_route: invalid proto {proto!r}")

    if dev_id and not dev:
        dev = fwutils.dev_id_to_linux_if_name(dev_id, support_unassigned_dev_id=True)
        if not dev:
            return (False, f"add_remove_route: interface was not found for dev_id {str(dev_id)}")

    if not via and not dev_id:
        return (False, "add_remove_route: interface or gateway are required")

    if addr == 'default':
        return (True, None)

    pppoe = fwpppoe.is_pppoe_interface(dev_id=dev_id)
    if dev and not fw_input_validation.is_valid_ifname(dev):
        return (False, f"add_remove_route: invalid device {dev!r}")

    if via and not pppoe:  # PPPoE interfaces can use any peer in the world as a GW, so escape sanity checks for it
        if not on_link and not fwutils.linux_check_gateway_exist(via):
            return (True, None)
        if not remove:
            tunnel_addresses = fwtunnel_stats.get_tunnel_info()
            if via in tunnel_addresses and tunnel_addresses[via] != 'up':
                return (True, None)

    if condition:
        route = FwConditionalRoute(condition, addr, via, dev, proto, metric, on_link, dev_id)
        if remove:
            route.uninstall()
        else:
            route.verify()
        return (True, None)

    routes_linux = FwLinuxRoutes(prefix=addr, preference=metric, proto=proto)
    route_in_linux = routes_linux.find(addr, metric, via)

    if add and route_in_linux:
        fwglobals.log.debug(f"route exists: {route_in_linux}")
        return (True, None)     # route to be added exist already

    if not route_in_linux:
        # WAN Monitor might increase the metric to 2.000.000.000+. Check if this is the case.
        #
        metric = metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK
        routes_linux  += FwLinuxRoutes(prefix=addr, preference=metric, proto=proto)
        route_in_linux = routes_linux.find(addr, metric, via)
        if remove and not route_in_linux:
            fwglobals.log.debug("route does not exists")
            return (True, None)     # route to be removed does not exist
        if add and route_in_linux:
            fwglobals.log.debug(f"route exists: {route_in_linux}")
            return (True, None)     # route to be added exist already

        # Now we should restore original metric for add operation.
        # Remove operation should stay with found metric, either original or watermarked,
        # so 'ip route del' could do the job.
        #
        metric = (metric - fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK) if add else route_in_linux.metric

    next_hops = ''
    if routes_linux:
        for route in routes_linux.values():
            if remove and via == route.via:
                continue
            next_hops += ' nexthop via ' + route.via

    if add:
        if via and via in next_hops:
            return (False, f"route to {addr} via {via} proto={proto} metric={metric} exists")
        if not via and next_hops:  # remove this check if customer want to support this case
            return (False, f"trial to replace route to {addr} via '{next_hops}' with route without VIA")

    if remove:
        if dev:  # If device was provided, delete specific route via this device only
            cmd = f"ip route del {addr} metric {metric} proto {proto} dev {dev}"
        else:    # Else delete all routes with same prefix and metric for all devices
            if not next_hops:
                cmd = f"ip route del {addr} metric {metric} proto {proto}"
            else:
                cmd = f"ip route replace {addr} metric {metric} proto {proto} {next_hops}"
    else:
        if via:
            next_hops = f'nexthop via {via}' + (f' dev {dev}' if dev else '') + next_hops
        elif dev:
            next_hops = f'dev {dev} ' + next_hops
        else:
            return (False, "neither VIA nor DEV was provided")
        on_link = 'onlink' if on_link else ''

        cmd = f"ip route replace {addr} metric {metric} proto {proto} {next_hops} {on_link}"

    try:
        fwglobals.log.debug(cmd)
        subprocess.check_call(cmd.split())   # all parameters were validated to be single words
    except Exception as e:
        if cmd.startswith('ip route del'):
            fwglobals.log.debug(f"'{cmd}' failed: {e}, ignore this error")
            return (True, None)
        return (False, str(e))

    # We need to re-apply Netplan configuration here to install default route that
    # could be removed in the flow before.
    # This will happen if static default route installed by user is exactly the same like
    # default route generated based on interface configuration inside Netplan file.
    if remove and re.match('0.0.0.0|default', addr):
        fwutils.netplan_apply("add_remove_route")

    return (True, None)

def add_remove_static_routes(via, is_add):
    routes_db = fwglobals.g.router_cfg.get_routes()

    for route in routes_db:
        if route['via'] != via:
            continue

        addr = route['addr']
        metric = str(route.get('metric', '0'))
        dev_id = route.get('dev_id')
        on_link = route.get('onLink', False)
        via = route['via']

        success, err_str = add_remove_route(addr, via, metric, not is_add, dev_id, 'static', on_link=on_link)
        if not success:
            fwglobals.log.error(f"failed to add/remove static route ({str(route)}): {err_str}")

def handle_fqdn_static_routes(params, prev_ip_addresses, ip_addresses):
    for ip_addr in prev_ip_addresses:
        try:
            route_params = dict(params)
            route_params['addr'] = f'{ip_addr}/32'
            install_uninstall_route(is_add=False, params=route_params)
        except Exception as e:
            fwglobals.log.error(f"failed to remove FQDN static route ({ip_addr}, {params}): {e}")

    for ip_addr in ip_addresses:
        try:
            route_params = dict(params)
            route_params['addr'] = f'{ip_addr}/32'
            install_uninstall_route(is_add=True, params=route_params)
        except Exception as e:
            fwglobals.log.error(f"failed to add FQDN static route ({ip_addr}, {params}): {e}")

def install_uninstall_route(is_add, params):
    addr      = params.get('addr')
    via       = params.get('via')
    dev_id    = params.get('dev_id')
    metric    = params.get('metric')
    on_link   = params.get('onLink')
    condition = params.get('condition')

    add_remove_route_params = {
        'addr': addr,
        'via': via,
        'metric': metric,
        'dev_id': dev_id,
        'on_link': on_link,
        'condition': condition
    }

    with FwCfgMultiOpsWithRevert() as handler:
        success, error = handler.exec(
            func=add_remove_route,
            params={**add_remove_route_params, 'remove': not is_add},
            revert_func=add_remove_route,
            revert_params={**add_remove_route_params, 'remove': is_add}
        )

        if not success:
            raise Exception(error)

        redistribute_ospf = params.get('redistributeViaOSPF')
        redistribute_bgp  = params.get('redistributeViaBGP')

        if redistribute_ospf:
            add_cmd    = f"access-list {fwglobals.g.FRR_OSPF_ACL} permit {addr}"
            remove_cmd = f"no access-list {fwglobals.g.FRR_OSPF_ACL} permit {addr}"

            success, error = handler.exec(
                func=fwutils.frr_vtysh_run,
                params={ 'commands': [add_cmd if is_add else remove_cmd ] },
                revert_func=fwutils.frr_vtysh_run,
                revert_params={ 'commands': [remove_cmd if is_add else add_cmd ] },
            )
            if not success:
                raise Exception(error)

        if redistribute_bgp:
            add_cmd    = f"access-list {fwglobals.g.FRR_BGP_ACL} permit {addr}"
            remove_cmd = f"no access-list {fwglobals.g.FRR_BGP_ACL} permit {addr}"

            success, error = handler.exec(
                func=fwutils.frr_vtysh_run,
                params={ 'commands': [add_cmd if is_add else remove_cmd ] },
                revert_func=fwutils.frr_vtysh_run,
                revert_params={ 'commands': [remove_cmd if is_add else add_cmd ] },
            )

            if not success:
                raise Exception(error)

