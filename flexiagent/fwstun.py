import sys
import os
import fwglobals
import fwtunnel_stats
import fwutils
import time

import fwthread
tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'tools')
sys.path.append(tools)
import stun

from fwobject import FwObject

class FwStunTimeouts():
    def __init__(self):
        self.reset_all              = 10 * 60
        self.update_cache_from_os   = 2 * 60
        self.send_stun              = 3
        self.probe_sym_nat          = 30
        self.send_sym_nat           = 3
        self.handle_down_tunnels    = 10
class FwStun(FwObject):
    'Class to handle STUN requests and responses'
    """
    The router configuration file contains a list of interfaces that are
    added to the system. We go over the file and scan for "add-interface" keys.
    For that key, we look for its IP address and GW address. If the interface has
    both IP address and GW address, it means it can access the internet. If this
    is the case, we need to find out, if we're behind NAT, what is the public
    IP and port of that address.
    So we add them to a section on a global cache, and sends STUN request for
    each of the addresses. For those we get an answer, we mark a 'success' flag.
    For those we did not, we start resending STUN requests, with increased delay
    between each. We start with 1 sec, then 2, then 4, and ends with 60. Once
    we reach 60 seconds, we continue sending re-transmission of the requests
    every 60 seconds. Note, those counters are managed for each of the addresses
    separately.

    From globals, we use the global cache where following elements are kept:
    {
        'local_ip':
        'gateway':
        'public_ip':
        'public_port':
        'send_time':
        'success':
        'server_index':
        'nat_type':
    }

    Note that for unassigned WAN interfaces we would also like to get public info, to display in UI.
    In that case, the address will be part of the STUN cache, but also part of the unassigned cache.
    More info can be found in unassigned_if.py
    """

    def __init__(self):
        """ Init function. This function inits the cache, gets the router-db handle
            and register callback and request names to listen too.

        """
        FwObject.__init__(self)
        self.stun_cache    = fwglobals.g.cache.stun_cache
        self.sym_nat_cache = fwglobals.g.cache.sym_nat_cache
        self.sym_nat_tunnels_cache = fwglobals.g.cache.sym_nat_tunnels_cache
        self.thread_stun   = None
        self.standalone    = not fwglobals.g.cfg.debug['agent']['features']['stun']['enabled']
        self.stun_retry    = 60
        self.timeouts      = FwStunTimeouts()
        stun.set_log(fwglobals.log)

    def _log_address_cache(self, dev_id=None):
        """Print the content of the local cache for WAN addresses.

        : param dev_id : (optional) If specified, only print data for the given dev_id.
        """
        if self.stun_cache:
            if dev_id:
                cache_data = self.stun_cache.get(dev_id)
                if cache_data and cache_data.get('local_ip') and cache_data.get('gateway'):
                    self.log.debug(f"{dev_id}: {cache_data}")
            else:
                for dev_id, cache_data in self.stun_cache.items():
                    local_ip = cache_data.get('local_ip')
                    gateway = cache_data.get('gateway')
                    if local_ip and gateway:
                        self.log.debug(f"{dev_id}: {cache_data}")
        else:
            self.log.debug("Stun_cache is empty")

    def initialize(self):
        """ Initialize STUN cache by sending STUN requests on all WAN interfaces before the first
        get-device-info is received. That way, the STUN cache will be ready with data when the
        system starts.
        After that, it starts the stun thread.
        """
        if self.standalone:
            return

        self.vxlan_port = fwutils.get_vxlan_port()

        self._initialize_stun_cache()

        stun.stun_servers_list = stun.STUN_SERVERS_SHORT_LIST  # reduce initialization time by using a few servers
        self._send_stun_requests()
        stun.stun_servers_list = stun.STUN_SERVERS

        self.thread_stun  = fwthread.FwThread(
                                            target=self.thread_stun_func,
                                            name='STUN',
                                            log=self.log)
        self.thread_stun.start()
        super().initialize()

    def _initialize_stun_cache(self):
        self.stun_cache.clear()
        ifaces, os_wan_ips = fwutils.get_all_interfaces()
        if ifaces:
            self.log.debug(f"_initialize_stun_cache: WAN IP list from OS: {str(os_wan_ips)}")
            for dev_id in ifaces:
                self.add_addr(dev_id, ifaces[dev_id].get('addr'), ifaces[dev_id].get('gw'))

    def update_vxlan_port(self, port):

        if self.standalone:
            return

        if port == self.vxlan_port:
            return
        self.vxlan_port = port

        self.sym_nat_cache.clear()
        self.sym_nat_tunnels_cache.clear()

        self._initialize_stun_cache()

    def finalize(self):
        stun.finalize()
        if self.thread_stun:
            self.thread_stun.stop()
            self.thread_stun = None
        super().finalize()

    def _update_cache_from_OS(self):
        """ Check the OS to find newly added/removed WAN interfaces and add/remove them
        to/from the cache
        """
        os_dev_id_dict, os_wan_ips = fwutils.get_all_interfaces()
        cache_ip_list       = [self.stun_cache[dev_id].get('local_ip') for dev_id in self.stun_cache \
                                if self.stun_cache[dev_id].get('local_ip') != '' and self.stun_cache[dev_id].get('gateway') != '']

        self.log.debug("_update_cache_from_OS: WAN IP list from OS %s" % (str(os_wan_ips)))
        self.log.debug("_update_cache_from_OS: WAN IP list from STUN cache %s" %(str(cache_ip_list)))

        # remove entry from cache if interface was removed from OS
        for dev_id in list(self.stun_cache.keys()):
            if dev_id not in os_dev_id_dict:
                del self.stun_cache[dev_id]

        # add updated IP from OS to Cache
        changed_flag = False
        for dev_id in os_dev_id_dict:
            if self.stun_cache.get(dev_id) and \
                os_dev_id_dict[dev_id].get('addr') == self.stun_cache[dev_id].get('local_ip') and \
                os_dev_id_dict[dev_id].get('gw') == self.stun_cache[dev_id].get('gateway'):
                continue
            else:
                addr = os_dev_id_dict[dev_id].get('addr')
                gw   = os_dev_id_dict[dev_id].get('gw')
                self.add_addr(dev_id, addr, gw)
                changed_flag = True
        if changed_flag == True:
            self._log_address_cache()

    def add_addr(self, dev_id, addr, gateway):
        """ Add address to cache.

        : param dev_id  : Bus address of the interface
        : param addr    : Wan address to add to cache for STUN requests
        : param gateway : gateway of addr
        """
        cached_addr = self.stun_cache.get(dev_id, {})
        if cached_addr.get('local_ip') != addr or cached_addr.get('gateway') != gateway:
            self.initialize_addr(dev_id, addr=addr, gateway=gateway, reset_server=True)

    def find_addr(self, dev_id):
        """ find address in cache, and return its params, empty strings if not found

        : param dev_id : interface bus address to find in cache.
        : return :  local_ip associated with this dev id address -> str
                    public_ip of a local address or emptry string -> str
                    public_port of a local port or empty string -> int
                    nat_type which is the NAT server the device is behind or empty string -> str
        """
        if self.standalone:
            #return empty info
            return '', '', ''

        if dev_id in self.stun_cache:
            c = self.stun_cache[dev_id]
            return c.get('public_ip'), c.get('public_port'), c.get('nat_type')
        else:
            return '', '', ''

    def initialize_addr(self, dev_id, addr='', gateway='', reset_server=False):
        """ resets info for a dev id address, as if its local_ip never got a STUN reply.
        We will use it everytime we need to reset dev id's data, such as in the case
        when we detect that a tunnel is disconnected, and we need to start sending STUN request
        for its local_ip. If the dev id address is already in the cache, its values will be over-written.

        Stun server and port will not be reset, because we want to map an address to the same
        STUN server, meaning an interface will send STUN requests to the same STUN server
        always, unless the STUN server went down or the request timed-out.

        : param dev_id : Bus address to reset in the cache.
        : return : the address entry in the cache -> dict
        """
        op = 'updated'
        if not dev_id in self.stun_cache:
            op = 'added'
            self.stun_cache[dev_id] = {}
        cached_addr = self.stun_cache[dev_id]

        cached_addr['local_ip']    = addr
        cached_addr['gateway']     = gateway
        cached_addr['public_ip']   = ''
        cached_addr['public_port'] = ''
        cached_addr['send_time']   = 0
        cached_addr['success']     = False

        if op == 'added' or reset_server:
            cached_addr.update({ 'server_index': 0, 'nat_type': '' })

        fwutils.set_linux_interfaces_stun(dev_id, '', '', '')

        self.log.debug(f"{dev_id}: {op}: address={addr}, gateway={gateway}")
        return cached_addr

    def _reset_all(self):
        """ reset all data in the STUN cache for every interface that is not part
        of a connected tunnel. If the tunnel will get disconnected, it will add
        the address back to the STUN cache and reset it.
        """
        tunnel_stats = fwtunnel_stats.tunnel_stats_get()
        tunnels      = fwglobals.g.router_cfg.get_tunnels()
        ip_up_set    = fwtunnel_stats.get_if_addr_in_connected_tunnels(tunnel_stats, tunnels)
        for (dev_id, cached_addr) in list(self.stun_cache.items()):
            # Do not reset info on interface participating in a connected tunnel
            if cached_addr.get('local_ip') in ip_up_set:
                continue
            # Check if the STUN request was successful before resetting
            if cached_addr.get('success') == True:
                self.initialize_addr(dev_id)

    def _handle_stun_none_response(self, dev_id):
        """ Handle non response after STUN request was sent.
        continue to retry every self.stun_retry seconds.

        : param dev_id : the Bus address associated with an IP address for which we did not receive
                      STUN reply
        """
        cached_addr = self.stun_cache.get(dev_id)
        if not cached_addr:
            return
        cached_addr['send_time'] = time.time() + self.stun_retry # next retry after 60 seconds
        cached_addr['success'] = False
        cached_addr['server_index'] = 0
        self.log.debug("_handle_stun_none_response: failed getting public IP/port for address %s, retry in %d seconds"\
             %(cached_addr['local_ip'], self.stun_retry))

    def _handle_stun_response(self, dev_id, p_ip, p_port, nat_type, st_index):
        """ Handle STUN response for an address. Reset all the counters,
        update the results, and set the 'success' flag to True.

        : param dev_id   : the bus address associated with the address for which we received STUN reply
        : param p_ip     : the public IP received from STUN reply
        : param p_port   : the public port received from STUN reply
        : param nat_type : the NAT type of the NAT the STUN request was passed through
        : param st_index : The index of the STUN server in the list of servers from which a
                           good response was received
        """
        cached_addr = self.stun_cache.get(dev_id)
        if not cached_addr:
            return

        self.log.debug(f"found external {p_ip}:{p_port} for {cached_addr['local_ip']}:{self.vxlan_port}")
        cached_addr['success']          = True
        cached_addr['send_time']        = 0
        cached_addr['nat_type']         = nat_type
        cached_addr['public_ip']        = p_ip
        cached_addr['public_port']      = p_port
        cached_addr['server_index']     = st_index

        fwutils.set_linux_interfaces_stun(dev_id, p_ip, p_port, nat_type)
        self._log_address_cache(dev_id)

    def _send_stun_requests(self):
        """ Send STUN request for each address that has no public IP and port
        updated in the cache. Sent only if the current time equals or greater than
        the calculated time it should be sent ('send_time').
        """
        for dev_id, cached_addr in self.stun_cache.items():

            if cached_addr.get('success') == True or cached_addr.get('gateway') == '' \
                or self._is_useStun(dev_id) == False:
                continue

            if time.time() >= cached_addr['send_time']:
                local_ip = cached_addr['local_ip']
                nat_type, nat_ext_ip, nat_ext_port, server_index = \
                    self._send_single_stun_request(local_ip, self.vxlan_port, cached_addr['server_index'])

                if fwglobals.g.router_threads.teardown:
                    self.log.debug("teardown: stop requests")
                    return  # handle shutdown in the middle _send_single_stun_request() loop

                if nat_ext_port == '':
                    self._handle_stun_none_response(dev_id)
                else:
                    self._handle_stun_response(dev_id, nat_ext_ip, nat_ext_port,
                            nat_type, server_index)

    def _send_single_stun_request(self, lcl_src_ip, lcl_src_port, stun_idx):
        """ sends one STUN request for an address.

        : param lcl_src_ip   : local IP address
        : param lcl_srt_port : local port
        : param stun_idx     : The STUN index in the list of STUN from which STUN requests will
                               be sent from
        : return :  nat_type     - nat type of the NAT -> str
                    net_ext_ip   - the public IP address -> str
                    nat_ext_port - the public port -> int
                    stun_index   - the STUN server's index in the list of servers -> int
        """
        dev_name = fwutils.get_interface_name(lcl_src_ip)
        if dev_name == None:
            return '','','',''

        self.log.debug("trying to find external %s:%s for device %s" %(lcl_src_ip,lcl_src_port, dev_name))

        nat_type, nat_ext_ip, nat_ext_port, stun_index = \
            stun.get_ip_info(lcl_src_ip, lcl_src_port, None, None, dev_name, stun_idx)

        return nat_type, nat_ext_ip, nat_ext_port, stun_index

    def thread_stun_func(self, ticks):
        """STUN thread
        Its function is to send STUN requests for address:{self.vxlan_port} in a timely manner
        according to some algorithm-based calculations.
        """
        # Don't STUN if vpp is being initializing / shutting down,
        # as querying vpp for interface names/ip-s might generate exception.
        if fwglobals.g.router_api.state_is_starting_stopping():
            return

        # send STUN requests for addresses that a request was not sent for
        # them, or for ones that did not get reply previously
        if ticks % self.timeouts.send_stun == 0:
            self._send_stun_requests()

        # run over all tunnels in not connected state and try to recover them
        if ticks % self.timeouts.handle_down_tunnels == 0:
            self._handle_down_tunnels()

        # probe tunnels in down state to see if we could find remote edge
        # address/port from incoming packets for symmetric NAT traversal

        if ticks % self.timeouts.send_sym_nat == 0:
            self._send_symmetric_nat()

        if ticks % self.timeouts.probe_sym_nat == 0:
            self._probe_symmetric_nat()

        if ticks % self.timeouts.reset_all == 0:
            # reset all STUN information every 10 minutes
            self._reset_all()

        if ticks % self.timeouts.update_cache_from_os == 0:
            # every update_cache_timeout, refresh cache with updated IP addresses from OS
            self._update_cache_from_OS()


    def _handle_down_tunnels(self):
        """ Run over all tunnels that are not connected and try to recover them.
        If it was disconnected due to changes in its source IP address, check if this IP address is still
        valid. If it is, add it to the STUN cache.
        """
        if self.standalone:
            return

        tunnels = fwglobals.g.router_cfg.get_tunnels()
        tunnel_stats = fwtunnel_stats.tunnel_stats_get()

        if not tunnels or not tunnel_stats:
            return

        self.sym_nat_tunnels_cache.clear()
        tun_dev_up_set = set()
        tun_dev_down_dict = {}

        # Get list of all IP addresses in the system
        ifaces, os_wan_ips = fwutils.get_all_interfaces()
        for tunnel in tunnels:
            tunnel_id = tunnel.get('tunnel-id')
            tunnel_stat = tunnel_stats.get(tunnel_id)
            if not tunnel_stat:
                #there is no stats for this tunnel yet so skip it
                continue
            if tunnel_stat.get('status') == 'up':
                # at least one tunnel is UP on this dev_id
                tun_dev_up_set.add(tunnel['dev_id'])
            else:
                # Down tunnel found. However, the tunnel might be disconnected due to changes in
                # source IP address. In that case, the current source address of the tunnel
                # is no longer valid. To make things safe, we check if the IP address exists
                # in the system. If it is not, no point on adding it to the STUN cache.
                if tunnel['src'] not in os_wan_ips:
                    self.log.debug("Tunnel %d is down, but its source address %s was not found in the system"\
                        %(tunnel_id, tunnel['src']))
                    continue

                # For IKEv2 tunnels, if we are behind symmetric NAT, and if we are IKE responder,
                # we have to send VxLAN packet to the remote end of the tunnel in order to pinhole the NAT.
                # Otherwise the remote end, which is IKE initiator, will be not able to intiate the IKE negotiation.
                encryption_mode = tunnel.get("encryption-mode", "psk")
                role = tunnel.get("ikev2", {}).get("role", "")
                if encryption_mode == "ikev2" and role == "responder":
                    self.log.debug("ikev2 tunnel %d responder side is down on dev %s"%(tunnel_id, tunnel['dev_id']))
                    self.sym_nat_tunnels_cache[tunnel_id] = {
                                'src'       : tunnel['src'],
                                'dst'       : tunnel['dst'],
                                'dstPort'   : tunnel['dstPort'],
                                'vni'       : self._get_vni(tunnel_id, encryption_mode)
                            }

                # at least one tunnel is DOWN on this dev_id
                tun_dev_down_dict[tunnel['dev_id']] = tunnel['src']

        # If all tunnels are UP, skip it while clearing the cache
        for dev_id in tun_dev_up_set:
            if dev_id not in tun_dev_down_dict:
                if self.stun_cache.get(dev_id):
                    self.stun_cache[dev_id]['success'] = True
                    self.stun_cache[dev_id]['send_time'] = 0
                if self.sym_nat_cache.get(dev_id):
                    self.sym_nat_cache['probe_time'] = 0

        for dev_id in tun_dev_down_dict.keys():

            # Force sending STUN request on behalf of the tunnel's source address
            if self.stun_cache.get(dev_id) and self.stun_cache[dev_id]['success'] == True:
                self.log.debug(f"Updating address on dev {dev_id} in STUN interfaces cache")
                self.stun_cache[dev_id]['success'] = False
                # it takes around 30 seconds to create a tunnel, so don't
                # start sending STUN requests right away
                self.stun_cache[dev_id]['send_time'] = time.time() + 30

            # Assume that remote edge is behind symmetric NAT
            # Try to discover remote edge ip and port from incoming packets.
            if self.sym_nat_cache.get(dev_id):
                if self.sym_nat_cache[dev_id]['probe_time'] == 0:
                    self.log.debug(f"Re-try to discover remote edge on dev {dev_id} ip {tun_dev_down_dict.get(dev_id)}")
                    self.sym_nat_cache[dev_id]['local_ip'] = tun_dev_down_dict.get(dev_id)
                    self.sym_nat_cache[dev_id]['probe_time'] = time.time() + 25
            else:
                self.log.debug(f"Try to discover remote edge on dev {dev_id} ip {tun_dev_down_dict.get(dev_id)}")
                self.sym_nat_cache[dev_id] = {
                            'local_ip'    : tun_dev_down_dict.get(dev_id),
                            'probe_time'  : time.time() + 25,
                        }


    def _is_useStun(self, dev_id):
        """ check router DB for 'useStun' flag for an interface bus address
        : param dev_id : Bus address to check the flag for
        : return : 'useStun' value in DB, or False if not found -> Bool
        """
        interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
        if interfaces and interfaces[0].get('useStun','') != '':
            return interfaces[0].get('useStun')

        if interfaces and interfaces[0].get('type','WAN') == 'LAN':
            return False

        # The dev_id was not found in the DB, so it is an unassigned interface. Let's check
        # if it has a GW configured. It so, it is a WAN interface, and we will return 'True'
        name = fwutils.dev_id_to_linux_if(dev_id)
        if not name:
            name = fwutils.dev_id_to_tap(dev_id, check_vpp_state=True)
        if not name:
            return False
        gw, _ = fwutils.get_interface_gateway(name)
        if not gw:
            return False
        return True

    def _get_vni(self, tunnel_id, encryption_mode):
        if encryption_mode == "none":
            return tunnel_id*2
        else:
            return tunnel_id*2+1

    def _probe_symmetric_nat(self):
        """ Assume that tunnel in down state has remote edge behind symmetric NAT.
            Try to discover the remote edge address/port from incoming packets.
        """
        if not fwglobals.g.router_api.state_is_started():
            return

        if not self.sym_nat_cache:
            return

        probe_tunnels = {}

        for dev_id in list(self.sym_nat_cache):
            cached_addr = self.sym_nat_cache.get(dev_id)
            if not cached_addr or cached_addr.get('probe_time', 0) == 0:
                continue

            if time.time() >= cached_addr['probe_time']:
                src_ip = cached_addr['local_ip']
                src_port = self.vxlan_port
                dev_name = fwutils.get_interface_name(src_ip)

                self.log.debug("Tunnel: discovering remote ip for tunnels with src %s:%s on device %s" \
                    %(src_ip, src_port, dev_name))
                probe_tunnels_dev = stun.get_remote_ip_info(src_ip, src_port, dev_name)
                self.log.debug("Tunnel: discovered tunnels %s on dev %s" %(probe_tunnels_dev, dev_name))
                probe_tunnels.update(probe_tunnels_dev)
                cached_addr['probe_time'] = 0

        self._handle_symmetric_nat_response(probe_tunnels)

    def _handle_symmetric_nat_response(self, probe_tunnels):
        """ Handle response for symmetric NAT probe. Reset all the counters,
        update the results, and set the 'success' flag to True.
        : param probe_tunnels  : List of discovered tunnels
        """
        tunnels       = fwglobals.g.router_cfg.get_tunnels()
        tunnel_stats  = fwtunnel_stats.tunnel_stats_get()
        if not tunnels or not probe_tunnels or not tunnel_stats:
            return

        for tunnel in tunnels:
            tunnel_id = tunnel['tunnel-id']
            encryption_mode = tunnel.get("encryption-mode", "psk")
            stats = tunnel_stats.get(tunnel_id)
            if stats and stats.get('status') == 'down':
                vni = self._get_vni(tunnel_id, encryption_mode)
                probe_tunnel = probe_tunnels.get(vni)
                if probe_tunnel:
                    new_ip, new_port = probe_tunnel["dst"], str(probe_tunnel["dstPort"])
                    if new_ip != tunnel['dst'] or new_port != tunnel['dstPort']:
                        self.log.debug("modify tunnel %d: dst %s:%s -> %s:%s" % \
                            (tunnel_id, tunnel['dst'], tunnel['dstPort'], new_ip, new_port))
                        request = {
                            "message": "modify-tunnel",
                            "params": {
                                "tunnel-id": tunnel_id,
                                "dst":       new_ip,
                                "dstPort":   new_port,
                            }
                        }
                        fwglobals.g.handle_request(request)

    def _send_symmetric_nat(self):
        """ For IKEv2 tunnels, if we are behind symmetric NAT, and if we are IKE responder,
            we have to send VxLAN packet to the remote end of the tunnel in order to pinhole the NAT.
            Otherwise the remote end, which is IKE initiator, will be not able to intiate the IKE negotiation.
        """
        if not fwglobals.g.router_api.state_is_started():
            return

        if not self.sym_nat_tunnels_cache:
            return

        for tunnel_id, tunnel in list(self.sym_nat_tunnels_cache.items()):
            src_ip = tunnel['src']
            dev_name = fwutils.get_interface_name(src_ip)
            if dev_name == None:
                # dev_name is None because tunnel is deleted, skip
                continue
            src_port = self.vxlan_port
            dst_ip = tunnel['dst']
            dst_port = int(tunnel['dstPort'])
            vxLanVni      = '%x' % (tunnel['vni'])
            vxLanMsgType  = '08000000'
            vxLanReserved = '00'
            msg = vxLanMsgType + vxLanVni.zfill(6) + vxLanReserved
            fwutils.send_udp_packet(src_ip, src_port, dst_ip, dst_port, dev_name, msg)
