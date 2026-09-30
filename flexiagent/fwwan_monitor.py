#! /usr/bin/python3

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

import copy
import re
import time

from urllib import parse as uparse

import subprocess

import fw_input_validation
import fwglobals
import fwnetplan
import fwpppoe
import fwroutes
import fwthread
import fwutils

from fwobject import FwObject

class FwWanMonitorRoute(fwroutes.FwRoute):
    def __init__(self, route, servers, probe_timeout, probe_count, threshold):
        fwroutes.FwRoute.__init__(self, route.prefix, route.via, route.dev, route.proto, route.metric, dev_id=route.dev_id)
        self.ok             = True      # If True there is connectivity to internet
        self.stats          = {'ifname': '', 'rtt': 0, 'drop_rate':0, 'connected': False}    # Connectivity stats results
        self.stale          = 0         # Counter of thread iterations where route was not found in OS
        self.servers        = None
        self.current_server = 0

        self.WATERMARK      = fwglobals.g.wan_monitor.WATERMARK

        self.tunnel_id = None if self.dev_id else self._get_tunnel_id()
        self.device_id = self.dev_id if self.dev_id else self.tunnel_id

        self.probes           = {}        # Ping results per server
        self.probe_timeout    = None
        self.probe_count      = None
        self.threshold        = None

        self.hysteresis_delay = 30
        self.approx_factor    = 16
        self.hysteresis_loss  = 1

        self.set_monitoring_config(servers, probe_timeout, probe_count, threshold)

    def _get_tunnel_id(self):
        tunnels = fwglobals.g.router_cfg.get_tunnels(loopback_ip=self.via)
        if not tunnels:
            return
        return tunnels[0].get('tunnel-id')

    def set_monitoring_config(self, servers, probe_timeout, probe_count, threshold):
        self.probe_timeout = probe_timeout

        reset_probes = False

        if probe_count != self.probe_count:
            self.probe_count = probe_count
            reset_probes = True

        if threshold != self.threshold:
            self.threshold = threshold
            reset_probes = True

        if servers != self.servers:
            self.servers = servers
            reset_probes = True

        if reset_probes:
            self.probes = {}
            # Be optimistic and assume connectivity to all servers are OK
            timestamp = time.time()
            for server in self.servers:
                self.probes[server] = {
                    'probes': [(True,timestamp)] * self.probe_count,
                    'ok': True
                }

    def get_next_server(self):
        if len(self.servers) <= 0:
            return None
        self.current_server = (self.current_server + 1) % len(self.servers)
        return self.servers[self.current_server]

    def update_connectivity(self, server, is_ok, timestamp):
        self.probes[server]['probes'].append((is_ok,timestamp))
        del self.probes[server]['probes'][0]  # Keep WINDOWS SIZE

        # Deduce connectivity status to specific server.
        # We use following hysteresis:
        # if connected, THRESHOLD failures is needed to deduce "no connectivity";
        # if not connected, THRESHOLD successes is needed to deduce "connectivity is back"
        #
        successes = len([t for t in self.probes[server]['probes'] if t[0] == True])
        failures  = len(self.probes[server]['probes']) - successes

        if self.probes[server]['ok'] and failures >= self.threshold:
            self.probes[server]['ok'] = False
        elif not self.probes[server]['ok'] and successes >= self.threshold:
            self.probes[server]['ok'] = True

        # Deduce connectivity status for route based on statuses of all servers:
        # At least one responding server is enough to report positive connectivity.
        #
        connected = False
        for server in self.probes.values():
            if server['ok']:
                connected = True
                break

        self.stats['connected'] = connected
        return connected

    def _update_rtt_stats(self, server, new_rtt):
        ifname = self.stats.get('ifname')
        if not ifname:
            if self.dev_id:
                ifname = fwutils.dev_id_to_vpp_if_name(self.dev_id)
            elif self.tunnel_id:
                ifname = fwutils.tunnel_to_vpp_if_name(self.tunnel_id)
            if not ifname:
                self.log.debug(f"WAN Monitor: Cannot get VPP interface name for {self.dev}")
                return
            self.stats['ifname'] = ifname

        old_rtt = self.stats.get('rtt', 0.0)
        rtt = new_rtt if not old_rtt  else old_rtt + (new_rtt - old_rtt) / self.approx_factor

        successes = len([t for t in self.probes[server]['probes'] if t[0] == True])
        failures  = len(self.probes[server]['probes']) - successes

        old_drop_rate = self.stats.get('drop_rate', 0)
        new_drop_rate = 100.0 * float(failures) / float(self.probe_count)
        drop_rate = round(float(old_drop_rate + new_drop_rate) / 2, 2)
        # if "old_drop_rate" > 0.0 and "new_drop_rate"  == 0.0,
        # the average will never be 0.0 and it is always 0.01.
        # Hence, if average is lower than 1, we consider it as 0.0
        #
        drop_rate = drop_rate if drop_rate > 1 else 0.0

        self.stats['drop_rate'] = drop_rate
        self.stats['rtt'] = rtt

        update = False
        if abs(round(drop_rate) - round(old_drop_rate)) >= self.hysteresis_loss:
            update = True
        elif abs(round(rtt) - round(old_rtt)) >= self.hysteresis_delay:
            update = True

        if fwglobals.g.policies.quality_rules > 0 and update:
            vppctl_cmd = 'fwabf quality %s loss %s delay %s jitter %s' % (ifname, round(drop_rate), round(rtt), 0)
            fwutils.vpp_cli_execute([vppctl_cmd])

    def check_connectivity(self):
        self.finish_probe(self.start_probe())

    def start_probe(self):
        """Starts connectivity probe - the 'fping' process - to the next server.
        The probe result is collected by finish_probe(). Splitting the probe into
        two steps enables running probes for all routes simultaneously.

        :returns: the probe context to be provided to finish_probe().
        """
        server_address = self.get_next_server()
        probe = {'server': server_address, 'timestamp': time.time(), 'process': None, 'output': ''}
        # The server and timeout come from the link monitor configuration,
        # so run fping without shell and validate them to avoid injection.
        if fw_input_validation.is_valid_ping_host(server_address) and \
           fw_input_validation.is_valid_int(self.probe_timeout, 0):
            cmd = ['fping', server_address, '-C', '1', '-q', '-R', '-I', str(self.dev), '-t', str(self.probe_timeout)]
            try:
                probe['process'] = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        universal_newlines=True)
            except Exception as e:
                probe['output'] = str(e)
        else:
            self.log.debug(f"WAN Monitor: invalid server {server_address!r} or timeout {self.probe_timeout!r}")
        return probe

    def finish_probe(self, probe):
        """Waits for the probe started by start_probe() to finish and updates
        connectivity status and route metric according to the probe result.
        """
        server_address = probe['server']
        timestamp      = probe['timestamp']
        output         = probe['output']
        process        = probe['process']
        if process:
            try:
                output, _ = process.communicate(timeout=60)
            except Exception as e:
                process.kill()
                process.communicate()
                output = str(e)

        new_rtt = 0.0
        rows = output.strip().splitlines()
        if rows:
            rtts = []
            for row in rows:
                host_rtt = [x.strip() for x in row.strip().split(':')]
                try:
                    float_rtt = float(host_rtt[1])
                except ValueError:
                    float_rtt = 0.0
                rtts.append(float_rtt)
            new_rtt = sum(rtts) / len(rtts) if len(rtts) > 0 else 0

        ok = (new_rtt > 0)
        is_connected = self.update_connectivity(server_address, ok, timestamp)

        # Now go and update metric of route, if connectivity was changed
        #
        new_metric = None
        if self.metric < self.WATERMARK and not is_connected:
            new_metric = self.metric + self.WATERMARK
            self.log.debug(f"WAN Monitor: Link down Metric Update - From: {self.metric} To: {new_metric}" )
        elif self.metric >= self.WATERMARK and is_connected:
            new_metric = self.metric - self.WATERMARK
            self.log.debug(f"WAN Monitor: Link up Metric Update - From: {self.metric} To: {new_metric}")

        if new_metric is not None:
            state = 'lost' if new_metric >= self.WATERMARK else 'restored'
            self.log.debug(f"connectivity {state} on {self.dev}")
            self._update_metric(new_metric)

        # update statistics for QBR on DIA links if VPP is started and interface is assigned
        if not fwglobals.g.router_api.state_is_started() or not fwutils.is_interface_assigned_to_vpp(self.dev_id):
            return

        self._update_rtt_stats(server_address, new_rtt)

    def _update_metric(self, new_metric):
        '''Update route in Linux and in vpp with new metric that reflects lost
        or restore of connectivity.

        :param route:   the route to be updated with new metric
        :param new_metric:  the new metric
        '''
        old_metric = self.metric
        self.log.debug(f"'{str(self)}' update metric: {old_metric} -> {new_metric}")

        # Firstly update the route status, so if get_wan_failover_metric() is called
        # from the other thread it will reflect the actual status.
        #
        prev_ok  = self.ok
        self.ok = new_metric < self.WATERMARK

        # Go and update Linux.
        # Note we do that directly by 'ip route del' command
        # and not relay on 'netplan apply', as in last case VPPSB does not handle
        # properly kernel NETLINK messages and does not update VPP FIB.
        #
        success = self.update(new_metric)
        if not success:
            self.ok = prev_ok
            self.log.error(f"failed to modify metric in OS for {self.dev}: {self.metric} -> {new_metric}")
            return

        fwutils.clear_linux_interfaces_cache()

        # If vpp runs and interface is under vpp control, i.e. assigned,
        # go and adjust vpp configuration to the newer metric.
        # Note the route does not have dev_id for virtual interfaces that are
        # created in vpp/vvpsb by tap-inject for tapcli-X interfaces used for
        # LTE/WiFi devices. These interfaces are assigned too.
        #
        interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=self.dev_id) if self.dev_id else []
        assigned = (not self.dev_id) or (interfaces)
        is_pppoe = fwpppoe.is_pppoe_interface(dev_id=self.dev_id)
        if fwglobals.g.router_api.state_is_started() and assigned and not is_pppoe:

            # Update netplan yaml-s in order to:
            # 1. Ensure that if 'netplan apply' is called due to some reason
            #    like received 'modify-interface' for other interface the new
            #    metric will be not overrode.
            # 2. Keep interface rule in routing table in sync with metric in default route:
            #       default via 192.168.43.1 dev vpp1 proto dhcp src 192.168.43.99 metric 600
            #       192.168.43.1 dev vpp1 proto dhcp scope link src 192.168.43.99 metric 600
            #
            # Note, we don't save metric into netplan, if the route was installed
            # by user using the 'add-route' request (we call such routes static routes).
            # This is to simplify code, as in this case there is no need to synchronize
            # static route database with WAN monitor / netplan database.
            # Implement that on demand :)
            #
            static_route = fwglobals.g.router_cfg.get_routes(addr=self.prefix, via=self.via, dev_id=self.dev_id)
            if not static_route:
                try:
                    name = fwutils.dev_id_to_tap(self.dev_id) # as vpp runs we fetch ip from taps
                    if not name:
                        name = self.dev

                    ip   = fwutils.get_interface_address(name, log=False)
                    proto = self.proto
                    dhcp = 'yes' if proto == 'dhcp' else 'no'
                    via = self.via

                    ifc = interfaces[0] if interfaces else {}
                    mtu = ifc.get('mtu')
                    dns_servers  = ifc.get('dnsServers', [])
                    # If for any reason, static IP interface comes without static dns servers, we set the default automatically
                    if dhcp == 'no' and len(dns_servers) == 0:
                        dns_servers = fwglobals.g.DEFAULT_DNS_SERVERS
                    dns_domains  = ifc.get('dnsDomains', None)

                    (success, err_str) = fwnetplan.add_remove_netplan_interface(\
                                        True, self.dev_id, ip, via, new_metric, dhcp,
                                        'WAN', dns_servers, dns_domains,
                                        mtu, if_name=self.dev)

                    if not success:
                        self.ok = prev_ok
                        self.log.error(f"failed to update metric in netplan: {err_str}")
                        return
                except Exception as e:
                    self.log.error(f"_update_metric failed: {str(e)}")

        self.log.debug(f"'{str(self)}' update metric: {old_metric} -> {new_metric} - done")

class FwWanMonitor(FwObject):
    """This object monitors internet connectivity over default WAN interface,
    and if bad connectivity is detected, it updates routing table to use
    other WAN interface with lowest metric. Than the 'bad' interface is monitored
    to detect the connectivity restore. When it is detected, the routing table
    is updated back with original default route rule.
        To monitor internet connectivity we just ping 1.1.1.1 and 8.8.8.8.
        To get 'bad' default route out of service we increase it's metric to
    be (2.000.000.000 + original metric), so it is still can be used for pings.
    The 2.000.000.000 threshold is derived as a 1/2 of the max u32 value,
    supported by Linux for metrics.
    """
    def __init__(self):
        """Constructor.

        """
        FwObject.__init__(self)

        self.disabled     = not fwglobals.g.cfg.debug['agent']['features']['wan_monitor']['enabled']

        # Make few shortcuts to get more readable code
        #
        self.WATERMARK       = fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK

        self.routes = fwglobals.g.cache.wan_monitor['enabled_routes']
        self.disabled_routes = fwglobals.g.cache.wan_monitor['disabled_routes']
        self.route_rule_re   = re.compile(r"(\w+) via ([0-9.]+) dev (\w+)(.*)") #  'default via 20.20.20.22 dev enp0s9 proto dhcp metric 100'
        self.thread_wan_monitor = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self.finalize()

    def initialize(self):
        if self.disabled:
            return
        self.thread_wan_monitor = fwthread.FwRouterThread(target=self._wan_monitor_thread_func, name="WAN Monitor", log=self.log)
        self.thread_wan_monitor.start()
        super().initialize()

    def finalize(self):
        """Destructor method
        """
        if self.disabled:
            return
        if self.thread_wan_monitor:
            self.thread_wan_monitor.join()
            self.thread_wan_monitor = None
        super().finalize()

    def get_stats(self):
        res = {}
        if self.disabled:
            return res

        for route in self.routes:
            device_id = str(self.routes[route].device_id) # must be str for device stats reply
            res[device_id] = self.routes[route].stats
        return res

    def _wan_monitor_thread_func(self, ticks):
        routes = self._get_routes()

        # Start probes on all routes simultaneously and then collect results,
        # so the pass takes time of the slowest probe and not the sum of all probes.
        #
        probes = []
        for r in routes:
            if r.stale:  # the route does not present in OS currently
                continue
            modem = fwglobals.g.modems.get(r.dev_id, raise_exception_on_not_found=False)
            if modem and modem.is_resetting():
                continue
            probes.append((r, r.start_probe()))

        try:
            for r, probe in probes:
                r.finish_probe(probe)
        finally:
            # If finish_probe() raised exception, ensure no fping process is left behind
            for _, probe in probes:
                process = probe['process']
                if process and process.returncode is None:
                    try:
                        process.kill()
                        process.communicate()
                    except Exception:
                        pass

    def check_internet(self, use_default_threshold=True, device_id=None, time_window=None, min_probes=None):
        '''Checks if internet is reachable and works. Just checks that there are default routes
        that are OK from the PING perspective. In addition, if the 'url' was provided, ensures
        that DNS resolution works.

        :param use_default_threshold: WAN Monitor constantly pings number of servers to check
                              internet, while keeping last X probes for analysis (sliding window).
                              Than it deduces internet connectivity by some threshold - how much
                              probes of this X probes should be successful. Default is 12 of 20.
                              The 'use_threshold' argument enforces relying on this threshold
                              to deduce internet connectivity.
                              If it it False, the connectivity will be reported is there is at least
                              one successful probe. In other words the no connectivity is reported,
                              only if all probes failed.
        :param device_id:     dev_id of the WAN interface internet through which should be checked
        :param time_window:   this parameter limits number of latest probes taking for analysis
                              by time. In seconds.
        :param min_probes:    this parameter enforces no less then X last probes to be taken for
                              analysis. It has precedence over 'time_window' parameter.

        :returns: True if internet is considered as reachable, False if it is not,
                  None if reachability can't be deduced for some reason, e.g. not enough
                  data was collected yet or initialization was not finished yet.
        '''
        if self.disabled:
            return True     # user thinks that the internet is available always :)

        if device_id:
            monitor_route = self.routes.get(device_id)
            routes = [monitor_route] if monitor_route else []
        else:
            routes = list(self.routes.values())  # get a snapshot to work on it without locks

        if not routes:
            self.log.debug("check_internet: no WAN routes are available")
            return None # None to differentiate between "no internet" and "unknown".

        for r in routes:
            if use_default_threshold:   # use default threshold
                if r.ok:
                    return True
            else:                       # otherwise we use "at least one ok" threshold
                probes = copy.deepcopy(r.probes)
                for server in probes.keys():
                    server_probes = probes[server]['probes']
                    if time_window:     # take last <time> probes if requested
                        timestamp = time.time() - time_window
                        server_probes = [t for t in server_probes if t[1] > timestamp]
                    if min_probes and len(server_probes) < min_probes:
                        server_probes = probes[server]['probes'][-min_probes:]
                    if len([t[0] for t in server_probes if t[0] == True]) > 0:  # "at least one ok"
                        return True

        self.log.debug("check_internet: no usable WAN routes at the moment")
        return False

    def _get_routes(self) -> 'list[FwWanMonitorRoute]':
        '''Fetches routes from Linux and parses them into FwWanRoute objects.
        '''
        os_routes  = {}

        routes_linux = fwroutes.FwLinuxRoutes(prefix='0.0.0.0/0')
        self._fix_routes(routes_linux)

        for key, route in routes_linux.items():

            # Skip Null interface routes
            if route.dev_id == fwroutes.FRR_NULL_INTERFACE:
                continue

            interfaces       = None
            monitor_disabled = False

            # Tunnels use loopback interfaces that has no physical device, so dev_id should be None.
            # Filter out routes on tunnel interfaces unless user choose to monitors them
            #
            if not route.dev_id:
                if not route.proto == 'static': # we monitor only static default routes
                    continue
                static_routes = fwglobals.g.router_cfg.get_routes(addr='0.0.0.0/0', via=route.via)
                link_monitor_id = static_routes[0].get('monitorInternet') if static_routes else None
            else:
                interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=route.dev_id)
                link_monitor_id = interfaces[0].get('monitorInternet') if interfaces else None
                if interfaces:
                    monitor_disabled = link_monitor_id is None
                else: # unassigned interfaces
                    monitor_disabled = not fwglobals.g.cfg.WAN_MONITOR_UNASSIGNED_INTERFACES

            if link_monitor_id:
                link_monitor = fwglobals.g.system_cfg.get_link_monitors(link_monitor_id)
                conf = link_monitor[0].get('icmp') if link_monitor else {}
            else:
                conf = {}

            if link_monitor_id and not conf:
                self.log.debug(f"link monitor object is not found for {link_monitor_id}")

            servers     = conf.get('servers', fwglobals.g.cfg.WAN_MONITOR_SERVERS)
            timeout     = conf.get('timeout', fwglobals.g.cfg.WAN_MONITOR_PROBE_TIMEOUT)
            probe_count = conf.get('attempts', fwglobals.g.cfg.WAN_MONITORING_WINDOW_SIZE)
            threshold   = conf.get('threshold', fwglobals.g.cfg.WAN_MONITORING_THRESHOLD)

            monitor_route = FwWanMonitorRoute(route, servers, timeout, probe_count, threshold)
            if not monitor_route.dev_id and not monitor_route.tunnel_id:
                self.log.debug(f"_get_routes(): Skipping route due to unknown dev_id/tunnel_id. {monitor_route}")
                continue

            # Skip routes on interfaces where monitoring is disabled or on unassigned interfaces (if disabled in fwagent_conf.yaml)
            #
            if monitor_disabled:
                if not monitor_route.device_id in self.disabled_routes:
                    self.log.debug(f"disabled on {monitor_route.dev}({monitor_route.device_id})")
                    self.disabled_routes[monitor_route.device_id] = route
                continue
            # If monitoring was enabled again, log this.
            if not monitor_disabled and monitor_route.device_id in self.disabled_routes:
                self.log.debug(f"enabled on {monitor_route.dev}({monitor_route.device_id})")
                del self.disabled_routes[monitor_route.device_id]

            # if this route is known to us, update statistics from cache
            #
            if monitor_route.device_id in self.routes:
                cached = self.routes[monitor_route.device_id]

                # Before using the "probes" from the cache,
                # check if the server list has been changed by the user.
                # If it has, reset the probes and don't use the cached values.
                cached.set_monitoring_config(servers, timeout, probe_count, threshold)

                monitor_route.probes         = cached.probes
                monitor_route.current_server = cached.current_server
                monitor_route.ok             = cached.ok
                monitor_route.stats          = cached.stats
                monitor_route.stale          = 0
            else:
                self.log.debug(f"Start WAN Monitoring on '{route}'")

            # Finally store the route into cache.
            #
            self.routes[monitor_route.device_id] = monitor_route

            # Record keys of routes fetched from OS.
            # We will use them a bit later to remove stale routes from cache.
            #
            os_routes[monitor_route.device_id] = None

        # Remove stale routes from cache
        #
        stale_keys = list(set(self.routes.keys()) - set(os_routes.keys()))
        for key in stale_keys:
            self.routes[key].stale += 1
            if self.routes[key].stale < 4:
                # The route might disappear from OS temporary due to 'netplan apply'
                # run by fwagent for any reason. That happens because netplan has
                # flaw in design: it reruns DHCP negotiation on interfaces even
                # if they were not changed since previous 'netplan apply'.
                # During this renegotiation routes through these interfaces are
                # removed from OS.
                continue
            self.log.debug(f"Stop WAN Monitoring on '{str(self.routes[key])}'")
            del self.routes[key]

        return list(self.routes.values())

    def _fix_routes(self, routes):
        '''In DHCP case, when VPP does not run, the WAN failover mechanism might
        end up with duplicated entries in kernel:

                default via 192.168.1.1 dev enp0s3 proto dhcp src 192.168.1.171 metric 100
                default via 10.72.100.1 dev enp0s9 proto dhcp src 10.72.100.179 metric 300
                default via 10.72.100.1 dev enp0s9 proto dhcp metric 2000000300
                10.72.100.0/24 dev enp0s9 proto kernel scope link src 10.72.100.179
                10.72.100.1 dev enp0s9 proto dhcp scope link src 10.72.100.179 metric 300

        Note two "default via 10.72.100.1 dev enp0s9" rules.
        This might happen because FwWanMonitor does not update netplan files,
        when VPP does not run. It just updates kernel table on-the-fly by call
        to the bash command "ip route add/del/replace ...". So if FwWanMonitor
        detects no internet connectivity and replace rule with X metric with rule
        with 2,000,000,000 + X metric, and then networkd / netplan is restarted
        or the DHCP lease renewed, Linux will restore the original rule with
        metric X. And nobody will remove the FwWanMonitor rule
        with 2,000,000,000 + X metric.
            Therefore we have to check that condition and to fix it manually.
        The algorithm just removes the duplicated entry with X metric,
        if the entry with 2,000,000,000 + X metric exists. When internet
        connectivity is restored, the FwWanMonitor will replace
        the 2,000,000,000 + X entry with X.

        :param routes: the fwroutes.FwLinuxRoutes object that includes kernel
                       routing table. The _fix_routes() function removes
                       duplicated routes from both this object and from kernel.
        '''
        routes_by_dev = {}
        routes_to_remove = {}

        # Go over routes and find duplications
        #
        for route in routes.values():
            existing_route = routes_by_dev.get(route.dev)
            if not existing_route:
                routes_by_dev[route.dev] = route
            else:
                # Duplication was found.
                # Spot the route with X metric and store it aside to be removed
                # later from kernel.
                #
                if existing_route.metric < self.WATERMARK and route.metric >= self.WATERMARK:
                    routes_to_remove[existing_route.key] = existing_route
                    self.log.debug(f"_fix_routes: going to remove duplicate '{str(existing_route)}' of '{str(route)}'")
                elif existing_route.metric >= self.WATERMARK and route.metric < self.WATERMARK:
                    self.log.debug(f"_fix_routes: going to remove duplicate '{str(route)}' of '{str(existing_route)}'")
                    routes_to_remove[route.key] = route

        # Remove duplications from the 'routes' object and from kernel
        #
        for key, route in routes_to_remove.items():
            route.uninstall()
            del routes[key]

def get_wan_failover_metric(metric, dev_id=None, tunnel_id=None):
    '''Fetches the metric of the default route on the device with specified dev_id.
    The metric might be the real one configured by user on flexiManage
    if internet is reachable via this device, or it can be the watermarked metric
    (the configured by user + WATERMARK) if internet is not reachable.

    :param metric    :  the original metric configured by user
    :param dev_id    :  Dev ID identifier of the wan monitoring.
    :param tunnel_id :  Identifier of the wan monitoring. Can be dev_id or tunnel number
    '''
    if not dev_id and not tunnel_id:
        return metric

    if dev_id:
        route = fwglobals.g.cache.wan_monitor['enabled_routes'].get(dev_id)
    else:
        route = fwglobals.g.cache.wan_monitor['enabled_routes'].get(tunnel_id)

    if not route or route.ok or metric >= fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK:
        return metric
    return (metric + fwglobals.g.WAN_FAILOVER_METRIC_WATERMARK)
