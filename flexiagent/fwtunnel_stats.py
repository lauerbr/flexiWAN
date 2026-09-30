#################################################################################
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
from netaddr import IPNetwork
from subprocess import Popen, PIPE, DEVNULL
import fw_input_validation
import fwglobals
import fwutils

from fwwatchdog import FwRlock

tunnel_stats_global = {}
tunnel_stats_global_lock = FwRlock("tunnel_stats")
fping_processes = {}

TIMEOUT = 15
WINDOW_SIZE = 30
APPROX_FACTOR = 16
HYSTERESIS_LOSS = 1
HYSTERESIS_DELAY = 30
PING_HOST_NUM = 200

def _stop_fping_process(process):
    """Kills fping process if it still runs and releases its resources."""
    try:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=1)
    except Exception:
        pass

def _prune_fping_processes(active_ids):
    """Stops and removes fping processes that belong to tunnels that are not
    monitored anymore, e.g. removed tunnels. Without that the 'fping_processes'
    dictionary grows forever.
    """
    for process_id in list(fping_processes.keys()):
        if process_id not in active_ids:
            _stop_fping_process(fping_processes.pop(process_id))

def _copy_stats_entry(entry):
    """Returns copy of tunnel statistics entry, that can be safely modified
    by tunnel_stats_test() without lock. Only the fields that are modified
    by tunnel_stats_test() are copied, the rest are shared with the original.
    It is much cheaper than copy.deepcopy() of the whole entry.
    """
    entry_copy = dict(entry)
    if 'drops' in entry_copy:
        entry_copy['drops'] = copy.copy(entry_copy['drops'])   # SlidingWindow is modified in place
    return entry_copy

def start_fping_process(cmd):
    """Execute a simple external command and get its output.

    :param cmd:         Command as list of arguments. It is executed without shell,
                        as it includes hosts and timeout from link monitor configuration.

    :returns: Command execution result.
    """
    process = Popen(cmd, stdin=DEVNULL, stdout=PIPE, stderr=PIPE, universal_newlines=True)
    return process

def _build_fping_cmd(hosts, timeout, interface=None):
    """Build fping argv. Invalid hosts (which might be interpreted by fping as
    options) are skipped and invalid timeout is replaced with default one."""
    hosts = [h for h in hosts if fw_input_validation.is_valid_ping_host(h)]
    if not fw_input_validation.is_valid_int(timeout, 0):
        timeout = fwglobals.g.cfg.WAN_MONITOR_PROBE_TIMEOUT
    cmd = ['fping'] + hosts + ['-C', '1', '-q', '-t', str(timeout)]
    if interface is not None:
        cmd += ['-I', str(interface)]
    return cmd

def peer_stats_get_ping_time(tunnels):
    """Use fping to get RTT.

    :param tunnels:         IP addresses to ping.

    :returns: RTT values on success and 0 otherwise.
    """
    ret = {}

    # cmd output example: "10.100.0.64  : 2.12 0.51 2.14"
    # 10.100.0.64 - host and calculate avg(2.12, 0.51, 2.14) as rtt
    for tunnel in tunnels:
        interface = tunnel['interface']
        tunnel_id = tunnel['tunnel_id']
        hosts =  tunnel.get('hosts_to_ping')
        timeout = tunnel.get('ping_timeout', fwglobals.g.cfg.WAN_MONITOR_PROBE_TIMEOUT)
        rows = None

        # fping when it use with -q does not print anything to stderr if there is an error.
        # errors could happen because of unresolved domain, invalid IP, etc.
        # in case of such errors the "return_code" will be set to non-zero value.
        # in errors, we will set the rtt to 0.0 which means no response.
        return_code = None

        if not hosts:
            continue

        cmd = _build_fping_cmd(hosts, timeout, interface)
        if tunnel_id in fping_processes:
            if fping_processes[tunnel_id].poll() is not None:
                (output, errors) = fping_processes[tunnel_id].communicate()
                return_code = fping_processes[tunnel_id].returncode
                rows = errors.strip().splitlines()
                fping_processes[tunnel_id] = start_fping_process(cmd)
        else:
            fping_processes[tunnel_id] = start_fping_process(cmd)

        rtts = []
        if rows:
            for row in rows:
                host_rtt = [x.strip() for x in row.strip().split(':')]
                try:
                    float_rtt = float(host_rtt[1])
                except ValueError:
                    float_rtt = 0.0
                rtts.append(float_rtt)
        elif return_code and return_code != 0:
            rtts.append(0.0)

        if rtts:
            ret[tunnel_id] = sum(rtts) / len(rtts) if len(rtts) > 0 else 0
        else:
            ret[tunnel_id] = None

    return ret

def tunnel_stats_get_ping_time(tunnels):
    """Use fping to get RTT.
    :param tunnels:         IP addresses to ping.
    :returns: RTT values on success and 0 otherwise.
    """
    ret = {}

    if not tunnels:
        return ret

    tunnels_keys = list(tunnels.keys())

    for i in range(0, len(tunnels_keys), PING_HOST_NUM):
        hosts = " ".join(tunnels_keys[i:i+PING_HOST_NUM]).split()
        cmd = _build_fping_cmd(hosts, fwglobals.g.cfg.WAN_MONITOR_PROBE_TIMEOUT)

        # use tunnel_id from first element of hosts butch as process_id
        process_id = tunnels[tunnels_keys[i]]
        rows = []

        if process_id in fping_processes:
            if fping_processes[process_id].poll() is not None:
                (output, errors) = fping_processes[process_id].communicate()
                rows = errors.strip().splitlines()
                fping_processes[process_id] = start_fping_process(cmd)
        else:
            fping_processes[process_id] = start_fping_process(cmd)

        for row in rows:
            host_rtt = [x.strip() for x in row.strip().split(':')]
            try:
                float_rtt = float(host_rtt[1]) if host_rtt[1] != '-' else 0.0
            except ValueError:
                float_rtt = 0.0
            tunnel_id = tunnels.get(host_rtt[0])
            if tunnel_id:
                ret[tunnel_id] = float_rtt

    return ret

def tunnel_stats_clear():
    """Clear previously collected statistics.

    :returns: None.
    """
    with tunnel_stats_global_lock:
        tunnel_stats_global.clear()

def tunnel_stats_remove(tunnel_id):
    with tunnel_stats_global_lock:
        if tunnel_id in tunnel_stats_global:
            del tunnel_stats_global[tunnel_id]

def tunnel_stats_test():
    """Update RTT, drop rate and other fields for all tunnels.

    :returns: None.
    """
    if not tunnel_stats_global:
        if fping_processes:
            _prune_fping_processes(set())
        return

    tunnel_stats_global_copy = {}
    with tunnel_stats_global_lock:
        tunnel_stats_global_copy = { tunnel_id: _copy_stats_entry(entry) for tunnel_id, entry in tunnel_stats_global.items() }

    peers = []
    tunnels = {}
    for tunnel_id, tunnel_stats_entry in tunnel_stats_global_copy.items():
        if tunnel_stats_entry.get('vpp_peer_tunnel_name'):
            loopback_tap_name = tunnel_stats_entry.get('loopback_tap_name', None)
            monitoring = tunnel_stats_entry.get('monitoring', {})
            hosts_to_ping, timeout = get_peer_monitoring_conf(monitoring.get('icmp_monitor_id'), monitoring.get('http_monitor_id'))
            peers.append({
                'tunnel_id':tunnel_id,
                'interface':loopback_tap_name,
                'hosts_to_ping': hosts_to_ping,
                'ping_timeout': timeout
            })
        else:
            hosts = " ".join(tunnel_stats_entry.get('hosts_to_ping'))
            if hosts:
                tunnels[hosts] = tunnel_id

    # Remove fping processes of tunnels that are not monitored anymore.
    # Note fping processes of tunnels without peers are identified by id of
    # the first tunnel in the batch of PING_HOST_NUM tunnels.
    #
    active_ids = set([p['tunnel_id'] for p in peers if p.get('hosts_to_ping')])
    tunnels_keys = list(tunnels.keys())
    for i in range(0, len(tunnels_keys), PING_HOST_NUM):
        active_ids.add(tunnels[tunnels_keys[i]])
    _prune_fping_processes(active_ids)

    tunnel_rtt = peer_stats_get_ping_time(peers)
    tunnel_rtt.update(tunnel_stats_get_ping_time(tunnels))

    for tunnel_id, stats in tunnel_stats_global_copy.items():
        vpp_peer_tunnel_name = stats.get('vpp_peer_tunnel_name')
        if vpp_peer_tunnel_name:
            sw_if_index = fwutils.vpp_if_name_to_cached_sw_if_index(vpp_peer_tunnel_name, 'peer-tunnel')
            status = fwutils.vpp_get_interface_status(sw_if_index).get('admin')
            if 'status' not in stats or ('status' in stats and stats['status'] != status):
                stats['status'] = status
                if fwglobals.g.policies.quality_rules > 0:
                    loss = 100 if status == 'down' else stats.get('loss', 0)
                    vppctl_cmd = 'fwabf quality %s loss %u delay 0 jitter 0' % (vpp_peer_tunnel_name, loss)
                    fwutils.vpp_cli_execute([vppctl_cmd])

        rtt = tunnel_rtt.get(tunnel_id)
        if rtt is None:
            continue

        if rtt > 0:
            stats['drops'].add_datapoint(0)
            stats['subsequent_drops'] = 0
        else:
            stats['drops'].add_datapoint(1)
            stats['subsequent_drops'] += 1

        stats['rtt'] = stats['rtt'] + (rtt - stats['rtt']) / APPROX_FACTOR
        stats['drop_rate'] = 100.0 * stats['drops'].get_average()

        update = False
        if vpp_peer_tunnel_name:
            ifname = vpp_peer_tunnel_name
        else:
            ifname = stats['vpp_if_name']

        loss = round(stats['drop_rate'])
        delay = round(stats['rtt'])

        if abs(loss - stats['loss']) >= HYSTERESIS_LOSS:
            stats['loss'] = loss
            update = True
        elif  abs(delay - stats['delay']) >= HYSTERESIS_DELAY:
            stats['delay'] = delay
            update = True

        if fwglobals.g.policies.quality_rules > 0 and update:
            vppctl_cmd = 'fwabf quality %s loss %s delay %s jitter %s' % (ifname, loss, delay, 0)
            fwutils.vpp_cli_execute([vppctl_cmd])

    with tunnel_stats_global_lock:
        for tunnel_id in list(tunnel_stats_global.keys()):
            if tunnel_id in tunnel_stats_global_copy:
                tunnel_stats_global[tunnel_id] = tunnel_stats_global_copy[tunnel_id]

def tunnel_stats_get():
    """Return a new tunnel status dictionary.
    Update tunnel status based on timeout.

    :returns: dictionary of tunnel statistics.
    """
    tunnel_stats = {}

    # Only scalar values are read out of the global statistics, so there is
    # no need to deep copy them. Just read them under lock.
    #
    with tunnel_stats_global_lock:
        for tunnel_id, stats in tunnel_stats_global.items():
            tunnel_stats[tunnel_id] = {}
            tunnel_stats[tunnel_id]['rtt'] = stats.get('rtt')
            tunnel_stats[tunnel_id]['drop_rate'] = stats.get('drop_rate')

            status = stats.get('status')
            tunnel_stats[tunnel_id]['status'] = status if status else 'down'

            if tunnel_stats[tunnel_id]['rtt'] and tunnel_stats[tunnel_id]['rtt'] > 0:
                if ((stats['subsequent_drops'] > TIMEOUT)):
                    tunnel_stats[tunnel_id]['status'] = 'down'
                else:
                    tunnel_stats[tunnel_id]['status'] = 'up'

    return tunnel_stats

def get_if_addr_in_connected_tunnels(tunnel_stats, tunnels):
    """ get set of addresses that are part of any connected tunnels
    : param tunnel_stat : statistics of tunnels.
    : param tunnels     : list of tunnels and their properties
    : return : set of IP addresses part of connected tunnels
    """
    ip_up_set = set()
    if tunnels and tunnel_stats:
        for tunnel in tunnels:
            tunnel_id = tunnel.get('tunnel-id')
            if tunnel_id and tunnel_stats.get(tunnel_id):
                if tunnel_stats[tunnel_id].get('status') == 'up':
                    ip_up_set.add(tunnel['src'])
    return ip_up_set

def get_tunnel_info():
    """ get set of remote loopback addresses
    : return : set of remote loopback IP addresses
    """
    tunnel_stats     = tunnel_stats_get()
    tunnels          = fwglobals.g.router_cfg.get_tunnels()
    remote_loopbacks = dict()

    if not tunnels:
        return {}

    for tunnel in tunnels:
        tunnel_id = tunnel.get('tunnel-id')
        if 'peer' in tunnel:
            ip = str(IPNetwork(tunnel['peer']['addr']).ip)
        else:
            ip = fwutils.build_tunnel_remote_loopback_ip(tunnel['loopback-iface']['addr'])

        if tunnel_id in tunnel_stats:
            status = tunnel_stats[tunnel_id]['status']
        else:
            status = 'down'
        remote_loopbacks[ip] = status
    return remote_loopbacks


def _convert_urls_to_fqdns(urls):
    res = []
    for url in urls:
        fqdn = fwutils.url_extract_fqdn(url)
        if fqdn:
            res.append(fqdn)
        else:
            res.append(url) # assuming it is already fqdn
    return res

def get_peer_monitoring_conf(icmp_monitor_id, http_monitor_id):
    hosts_to_ping = []
    timeout = 1000

    if icmp_monitor_id:
        ip_monitor_conf = fwglobals.g.system_cfg.get_link_monitors(icmp_monitor_id)
        if ip_monitor_conf:
            hosts_to_ping += ip_monitor_conf[0].get('icmp', {}).get('servers', [])
            timeout = max(ip_monitor_conf[0].get('icmp', {}).get('timeout', 1000), timeout)

    if http_monitor_id:
        url_monitor_conf = fwglobals.g.system_cfg.get_link_monitors(http_monitor_id)
        if url_monitor_conf:
            hosts_to_ping += _convert_urls_to_fqdns(url_monitor_conf[0].get('http', {}).get('urls', []))
            timeout = max(url_monitor_conf[0].get('http', {}).get('timeout', 1000), timeout)

    return hosts_to_ping, timeout

def tunnel_stats_add(params):
    """Add tunnel statistics entry into a dictionary.

    :param params:         Tunnel parameters from Fleximanage.

    :returns: None.
    """
    stats_entry = dict()
    stats_entry['drop_rate'] = 0
    stats_entry['drops'] = fwutils.SlidingWindow(WINDOW_SIZE)
    stats_entry['subsequent_drops'] = TIMEOUT+1   # Enforce initial status of tunnel as 'down'
    stats_entry['rtt'] = 0
    stats_entry['loss'] = 0
    stats_entry['delay'] = 0

    if 'peer' in params:
        stats_entry['vpp_peer_tunnel_name'] = fwutils.peer_tunnel_to_vpp_if_name(params['tunnel-id'])
        stats_entry['loopback_tap_name'] = fwutils.tunnel_to_tap(params['tunnel-id'])
    else:
        stats_entry['vpp_if_name'] = fwutils.tunnel_to_vpp_if_name(params['tunnel-id'])

    if 'peer' in params:
        icmp_monitor_id  = params['peer'].get('icmpMonitor')
        http_monitor_id = params['peer'].get('httpMonitor')
        stats_entry['monitoring'] = {
            'icmp_monitor_id': icmp_monitor_id,
            'http_monitor_id': http_monitor_id
        }
    else:
        hosts_to_ping = [fwutils.build_tunnel_remote_loopback_ip(params['loopback-iface']['addr'])]
        stats_entry['hosts_to_ping'] = hosts_to_ping

    with tunnel_stats_global_lock:
        tunnel_stats_global[params['tunnel-id']] = stats_entry

def fill_tunnel_stats_dict():
    """Get tunnels their corresponding loopbacks ip addresses
    to be used by tunnel statistics thread.
    """
    tunnel_stats_clear()

    tunnels = fwglobals.g.router_cfg.get_tunnels()
    for params in tunnels:
        tunnel_stats_add(params)
