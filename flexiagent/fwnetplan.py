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
import glob
import os
import re
import shutil
import time
import yaml

import fw_os_utils
import fwglobals
import fwlte
import fwutils
import fwpppoe
import fwroutes

from fwwan_monitor import get_wan_failover_metric
from build.config import config

active_router_fn_extension = config.exec_file_suffix # .e.g "run"
edge_ui_backup_extension = config.netplan.edge_ui_backup_extension

# Define a custom opener function that sets the file permissions
# The 'mode' argument of os.open() is what controls the permissions
def _secure_opener(path, flags):
    '''
    A custom opener function to create a file with read/write permissions
    for the user only.

    Args:
        path (str): The path to the file.
        flags (int): The flags passed by the main open() call (e.g., os.O_RDWR).

    Returns:
        int: A file descriptor for the newly opened file.
    '''
    # The octal value 0o600 corresponds to 'rw-------' permissions:
    # r (4) + w (2) + x (0) for the user
    # r (0) + w (0) + x (0) for the group
    # r (0) + w (0) + x (0) for others
    # The integer value is 448.
    permissions = 0o600

    # We must also include the os.O_CREAT flag to ensure the file is created
    # if it doesn't already exist.
    # The 'flags' parameter from the open() call is passed to us, so we
    # just need to add the O_CREAT flag.
    return os.open(path, flags | os.O_CREAT, mode=permissions)

def _copyfile(source_name, dest_name, buffer_size=1024*1024):
    with open(source_name, 'r') as source, open(dest_name, 'w', opener=_secure_opener) as dest:
        while True:
            copy_buffer = source.read(buffer_size)
            if not copy_buffer:
                break
            fwutils.file_write_and_flush(dest, copy_buffer)

def backup_linux_netplan_files():
    for values in list(fwglobals.g.NETPLAN_FILES.values()):
        fname = values.get('fname')
        fname_backup = fname + '.fw_run_orig'
        fname_run = fname.replace('yaml', f'{active_router_fn_extension}.yaml')

        fwglobals.log.debug('_backup_netplan_files: doing backup of %s' % fname)
        if not os.path.exists(fname_backup):
            _copyfile(fname, fname_backup)
        if not os.path.exists(fname_run):
            _copyfile(fname, fname_run)
        if os.path.exists(fname):
            os.remove(fname)

    # Take recovery yaml to be out of service to avoid collision with vRouter configuration
    #
    if os.path.exists(fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE):
        shutil.move(fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE, fwglobals.g.NETPLAN_RECOVERY_FILE_SILENCED)

def restore_linux_netplan_files_created_by_vpp():
    '''
    Restores netplan files modified by vpp.
    Whenever vpp starts, the modified netplan files will receive the "run" (see "active_router_fn_extension") suffix
    (e.g. 01-netcfg.run.yaml) while the original netplan files have the backup
    extension of "run_orig" (01-netcfg.yaml.run_orig)
    '''
    files = glob.glob(f"/etc/netplan/*.{active_router_fn_extension}.yaml") + \
            glob.glob(f"/lib/netplan/*.{active_router_fn_extension}.yaml") + \
            glob.glob(f"/run/netplan/*.{active_router_fn_extension}.yaml")

    for fname in files:
        fname_run = fname
        fname = fname_run.replace(f'{active_router_fn_extension}.yaml', 'yaml')
        fname_backup = fname + '.fw_run_orig'

        if os.path.exists(fname_run):
            os.remove(fname_run)

        if os.path.exists(fname_backup):
            _copyfile(fname_backup, fname)
            os.remove(fname_backup)

    # Get recovery yaml back to service if it was suppressed
    #
    if os.path.exists(fwglobals.g.NETPLAN_RECOVERY_FILE_SILENCED):
        shutil.move(fwglobals.g.NETPLAN_RECOVERY_FILE_SILENCED, fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE)

    if files:
        fwutils.netplan_apply('restore_linux_netplan_files_created_by_vpp')
    return files

def restore_linux_netplan_files_created_by_edge_ui():
    '''
    Restores netplan files modified by edgeUI.
    Whenever users modify Linux interfaces using edgeUI, the prefix is
    baseline (01-netcfg.baseline.yaml) while the backup extension becomes "orig"
    (01-netcfg.yaml.orig)
    '''
    files = glob.glob("/etc/netplan/*.baseline.yaml") + \
            glob.glob("/lib/netplan/*.baseline.yaml") + \
            glob.glob("/run/netplan/*.baseline.yaml")

    for fname in files:
        fname_run = fname
        fname = fname_run.replace('baseline.yaml', 'yaml')
        fname_backup = fname + f'.{edge_ui_backup_extension}'

        if os.path.exists(fname_run):
            os.remove(fname_run)

        if os.path.exists(fname_backup):
            _copyfile(fname_backup, fname)
            os.remove(fname_backup)

    if files:
        fwutils.netplan_apply('restore_linux_netplan_files_created_by_edge_ui')
    return files


def netplan_get_filepaths():

    return glob.glob("/etc/netplan/*.yaml") + \
           glob.glob("/lib/netplan/*.yaml") + \
           glob.glob("/run/netplan/*.yaml")


def netplan_unload_assigned_ports(assigned_linux_interfaces):
    '''
    This function is called after the agent has backed up the netplan files and
    created "run.yaml" files that we will modify and work with during the router startup.

    In the "run" files, we keep the configurations of unassigned interfaces as they are.
    These files also include assigned interfaces with their Linux names, such as "eth0".

    In most cases, it's alright to have unconfigured assigned interfaces in netplan before the add-interface processes.
    This is because when the VPP service starts,
    the assigned interfaces (eth0) will no longer exist in Linux as they'll move to DPDK control.
    Therefore, "netplan apply" calls won't find those interfaces and won't make any changes.

    However, having some interfaces in the "run" files before the add-interface processing is problematic:
    - For "set-name", we must prevent interfaces from being renamed immediately after the creation of the Tap-inject module.
    - Non-DPDK interfaces (like WiFi) shouldn't have the old configuration now.
    In both cases, they'll be configured on the corresponding add-interface.

    Since we already have the old information in the backup files,
    there is no need for it to be in the "run" files.
    Hence, this function removes the assigned interfaces.

    params assigned_linux_interfaces: List of Linux interface names assigned to VPP
    '''
    files = netplan_get_filepaths()
    netplan_apply = False

    for fname in files:
        changed_ethernets = False
        changed_vlans = False
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    ethernets_updates = copy.deepcopy(ethernets)
                    for dev in ethernets:
                        if_name = ethernets[dev].get('set-name', dev)
                        if if_name in assigned_linux_interfaces:
                            del ethernets_updates[dev]
                            changed_ethernets = True
                            fwglobals.log.debug(f"netplan_unload_assigned_ports: Device: {if_name} File: {fname}")
                if 'vlans' in network:
                    vlans = network['vlans']
                    vlans_updates = copy.deepcopy(vlans)
                    for dev in vlans:
                        link = vlans[dev].get('link', '')
                        if link and link in assigned_linux_interfaces:
                            del vlans_updates[dev]
                            changed_vlans = True
                            fwglobals.log.debug(f"netplan_unload_assigned_ports: Vlan: {dev} File: {fname}")
        if changed_ethernets:
            config['network']['ethernets'] = ethernets_updates
        if changed_vlans:
            config['network']['vlans'] = vlans_updates
        if changed_ethernets or changed_vlans:
            with open(fname, 'w', opener=_secure_opener) as file_stream:
                yaml.dump(config, file_stream)
            netplan_apply = True

    if netplan_apply:
        fwutils.netplan_apply('netplan_unload_assigned_ports')


def load_netplan_filenames(read_from_disk=False, get_only=False):
    '''Parses currently active netplan yaml files into dict of device info by
    interface name, where device info is represented by tuple:
    (<netplan filename>, <interface name>, <gw>, <dev_id>, <set-name name>).
    Than the parsed info is loaded into fwglobals.g.NETPLAN_FILES cache.

    :param read_from_disk: if True it means that we need to fill the cache with the data that stored on the disk.
    :param get_only: if True the parsed info is not loaded into cache.
    '''

    if read_from_disk:
        netplan_filenames = fwglobals.g.db.get('netplan', {}).get('filenames')
        if netplan_filenames:
            fwglobals.log.debug("load_netplan_filenames: loading from disk. %s" % str(netplan_filenames))
            fwglobals.g.NETPLAN_FILES = dict(netplan_filenames)
            return fwglobals.g.NETPLAN_FILES

    devices = {}
    linux_routes = fwroutes.FwLinuxRoutes(prefix='0.0.0.0/0')
    for route in linux_routes.values():
        devices[route.dev] = route.via

    files = glob.glob("/etc/netplan/*.fw_run_orig") + \
            glob.glob("/lib/netplan/*.fw_run_orig") + \
            glob.glob("/run/netplan/*.fw_run_orig")

    if not files:
        files = glob.glob("/etc/netplan/*.yaml") + \
                glob.glob("/lib/netplan/*.yaml") + \
                glob.glob("/run/netplan/*.yaml")

    # Remove recovery yaml-s from processing - they should be invisible when VPP runs to avoid
    # colliding with vRouter configuration provided by user.
    # If recovery yaml uses unassigned interface to provide connectivity to internet, that might
    # break connectivity when vRouter runs. We will live with this for now, as this case has low
    # probability, but support for it complicates code a lot.
    #
    files = [f for f in files if not re.match(r'.*flexiwan.*recovery.*', f)]

    fwglobals.log.debug("load_netplan_filenames: %s" % files)

    our_files = {}
    for fname in files:
        with open(fname, 'r') as stream:
            if re.search('fw_run_orig', fname):
                fname = fname.replace('yaml.fw_run_orig', 'yaml')
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    for dev in ethernets:
                        name = ethernets[dev].get('set-name', '')
                        if name:
                            gateway = devices.get(name)
                            dev_id = fwutils.get_interface_dev_id(name)
                        else:
                            gateway = devices.get(dev)
                            dev_id = fwutils.get_interface_dev_id(dev)
                        if fname in our_files:
                            our_files[fname].append({'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name})
                        else:
                            our_files[fname] = [{'ifname': dev, 'gateway': gateway, 'dev_id': dev_id, 'set-name': name}]

    if get_only:
        return our_files

    fwglobals.g.NETPLAN_FILES.clear()

    for fname, devices in list(our_files.items()):
        for dev in devices:
            dev_id = dev.get('dev_id')
            ifname = dev.get('ifname')
            set_name = dev.get('set-name')
            if dev_id:
                fwglobals.g.NETPLAN_FILES[dev_id] = {'fname': fname, 'ifname': ifname, 'set-name': set_name}

    fwglobals.log.debug(f'load_netplan_filenames: {fwglobals.g.NETPLAN_FILES}')

    # Save the disk cache for use when needed
    netplan = fwglobals.g.db.get('netplan')
    if not netplan:
        fwglobals.g.db['netplan'] = {}
    netplan_db = fwglobals.g.db['netplan']  # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
    netplan_db['filenames'] = fwglobals.g.NETPLAN_FILES
    fwglobals.g.db['netplan'] = netplan_db

def _write_to_netplan_file(fname, config, **args):
    with open(fname, 'w', opener=_secure_opener) as stream:
        yaml.safe_dump(config, stream, **args)
        stream.flush()
        os.fsync(stream.fileno())

def _revert_netplan_file(fname, config, reason):
    fwglobals.log.error(reason)
    _write_to_netplan_file(fname, config)
    fwutils.netplan_apply(f"_revert_netplan_file: {reason}")

def _add_netplan_file(fname):
    if os.path.exists(fname):
        return

    config = dict()
    config['network'] = {'version': 2, 'renderer': 'networkd'}
    _write_to_netplan_file(fname, config, default_flow_style=False)

def _dump_netplan_file(fname):
    if fname:
        try:
            with open(fname, 'r') as f:
                fwglobals.log.error("NETPLAN file contents: " + f.read())
        except Exception as e:
            err_str = "_dump_netplan_file failed: file: %s, error: %s"\
              % (fname, str(e))
            fwglobals.log.error(err_str)

def _set_netplan_section_dhcp(config_section, dhcp, type, metric, ip, gw, dnsServers=None, dnsDomains=None, ignoreMtu=False):
    if 'dhcp6' in config_section:
        del config_section['dhcp6']

    nameservers = config_section.get('nameservers', {})
    if dnsServers:
        nameservers['addresses'] = dnsServers
        config_section['nameservers'] = nameservers

    if dnsDomains:
        nameservers['search'] = dnsDomains
        config_section['nameservers'] = nameservers

    if type == 'LAN' and 'gateway4' in config_section :
        del config_section['gateway4']

    if re.match('yes', dhcp):
        if 'addresses' in config_section:
            del config_section['addresses']
        if 'routes' in config_section:
            del config_section['routes']
        if 'gateway4' in config_section:
            del config_section['gateway4']

        config_section['dhcp4'] = True
        config_section['dhcp4-overrides'] = {'route-metric': metric}

        # If a user doesn't specify static DNS servers and domains, use DNS that received from DHCP
        if not dnsServers and not dnsDomains and 'nameservers' in config_section:
            del config_section['nameservers']

        # Override DNS info received from DHCP server with those configured by the user
        if dnsServers:
            config_section['dhcp4-overrides']['use-dns'] = False
        elif config_section.get('nameservers', {}).get('addresses'):
            del config_section['nameservers']['addresses']

        if dnsDomains:
            config_section['dhcp4-overrides']['use-domains'] = False
        elif config_section.get('nameservers', {}).get('search'):
            del config_section['nameservers']['search']

        if ignoreMtu:
            config_section['dhcp4-overrides']['use-mtu'] = False

        return config_section

    # Static IP
    config_section['dhcp4'] = False
    if 'dhcp4-overrides' in config_section:
        del config_section['dhcp4-overrides']

    if ip:
        config_section['addresses'] = [ip]
    elif 'addresses' in config_section:
        del config_section['addresses']

    if not gw or type != 'WAN':
        return config_section

    # WAN interface configuration
    default_route_found = False
    routes = config_section.get('routes', [])
    for route in routes:
        if route['to'] == '0.0.0.0/0':
            default_route_found = True
            route['metric']     = metric
            route['via']        = gw
            break
    if not default_route_found:
        routes.append({'to': '0.0.0.0/0', 'via': gw, 'metric': metric})
        config_section['routes'] = routes   # Handle case where there is no 'routes' section
    if 'gateway4' in config_section:
        del config_section['gateway4']

    return config_section

def add_remove_netplan_interface(is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains, mtu=None, if_name=None):
    '''
    :param metric:  integer (whole number)
    '''

    old_ethernets = {}
    type = type.upper()

    if fwutils.is_vlan_interface(dev_id=dev_id):
        return add_remove_netplan_vlan(is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains)

    if fwpppoe.is_pppoe_interface(dev_id=dev_id):
        err_str = "add_remove_netplan_interface: PPPoE interface %s is not supported" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    fwglobals.log.debug(
        "add_remove_netplan_interface: is_add=%d, dev_id=%s, ip=%s, gw=%s, metric=%d, dhcp=%s, type=%s, \
         dnsServers=%s, dnsDomains=%s, mtu=%s, if_name=%s" %
        (is_add, dev_id, ip, gw, metric, dhcp, type, dnsServers, dnsDomains, str(mtu), if_name))

    fo_metric = get_wan_failover_metric(metric, dev_id=dev_id)
    if fo_metric != metric:
        fwglobals.log.debug(
            "add_remove_netplan_interface: dev_id=%s, use wan failover metric %d" % (dev_id, fo_metric))
        metric = fo_metric

    set_name = ''
    old_ifname = ''
    ifname = if_name if if_name else fwutils.dev_id_to_tap(dev_id)
    if not ifname:
        err_str = "add_remove_netplan_interface: %s was not found" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    dev_id = fwutils.dev_id_to_full(dev_id)
    if dev_id in fwglobals.g.NETPLAN_FILES:
        fname = fwglobals.g.NETPLAN_FILES[dev_id].get('fname')
        fname_run = fname.replace('yaml', f'{active_router_fn_extension}.yaml')
        _add_netplan_file(fname_run)

        fname_backup = fname + '.fw_run_orig'

        old_ifname = fwglobals.g.NETPLAN_FILES[dev_id].get('ifname')
        set_name   = fwglobals.g.NETPLAN_FILES[dev_id].get('set-name', '')

        with open(fname_backup, 'r') as stream:
            old_config = yaml.safe_load(stream)
            old_network = old_config['network']
            old_ethernets = old_network['ethernets']
    else:
        fname_run = fwglobals.g.NETPLAN_FILE
        _add_netplan_file(fname_run)

    try:
        with open(fname_run, 'r') as stream:
            config = yaml.safe_load(stream)
            old_config = copy.deepcopy(config)
            network = config['network']
            network['renderer'] = 'networkd'

        if 'ethernets' not in network:
            network['ethernets'] = {}

        ethernets = network['ethernets']

        config_section = {}
        if old_ethernets:
            if old_ifname in old_ethernets:
                config_section = dict(old_ethernets[old_ifname])

        if mtu:
            config_section['mtu'] = mtu

        # Configure DHCP related logic
        ignoreMtu = True if mtu else False
        config_section = _set_netplan_section_dhcp(config_section, dhcp, type, metric, ip,
                                                   gw, dnsServers, dnsDomains, ignoreMtu)

        # Note, for the LTE interface we have two interfaces.
        # The physical interface (wwan0) and the vppsb(vppX) interface.
        # Both of them have the same dev_id, so we return True from `is_lte_interface()` for both of them.
        # We set the IP configuration only on the vppsb.
        # But if the user has configured in the netplan file also the LTE with set-name option,
        # we need to make sure that in any action, of any kind, that set-name will apply to the physical interface.
        # Note the comments below in the appropriate places.
        is_lte = fwlte.is_lte_interface_by_dev_id(dev_id)

        if is_add == True:
            '''
            With 'set-name' attribute or not, the main name shall not be changed. Example below:
            enp0s3:
                 set-name: wan3
            After VPP start, Changed as:
            vpp<x>:
                 set-name: wan3
            '''
            if old_ifname in ethernets:
                del ethernets[old_ifname]

            if set_name and is_lte:
                # For LTE interface with set-name we need to keep the `set-name` on the physical interface and not for the vppsb (see explanation above).
                # The part of LTE in netplan should look like this
                # vpp3 (vppsb interface):
                #   addresses: [100.96.96.225/30]
                #   dhcp4: false
                #   mtu: 1500
                #   nameservers:
                #     addresses: [91.205.152.174, 91.205.152.204]
                #   routes:
                #   - {metric: 0, to: 0.0.0.0/0, via: 100.96.96.226}
                # wwan0 (physical interface)::
                #   match: {macaddress: '1e:10:c7:a5:5a:c7'}
                #   set-name: WANLTE
                del config_section['set-name']
                del config_section['match'] # set-name requires 'match' property
                ethernets[ifname] = config_section

                # Keep the old_ifname for LTE (wwan0 e.g) in order to apply the set-name for this interface.
                # So for lte with set-name both interfaces should be listed in netplan files.
                # The physical interface with set-name, and the vppsb (vppX) with IP configuration.
                if old_ethernets and old_ifname in old_ethernets:
                    ethernets[old_ifname] = old_ethernets[old_ifname]

                    # When vpp runs, we don't need the nameservers on the physical interface but the vppsb
                    if 'nameservers' in ethernets[old_ifname]:
                        del ethernets[old_ifname]['nameservers']
            else:
                ethernets[ifname] = config_section
        else:
            # This part of the function is executed when the VPP is running, and we will not stop it.
            # This means that the interface will remain under VPP control and will not be released to Linux control.
            # Hence, when we come to remove an interface, the intention is only to clear its configuration.
            if ifname in ethernets:
                ethernets[ifname] = {}
                ethernets[ifname]['dhcp4'] = False

                # Explanation about LTE with set-name:
                # when we want to remove it from netplan, we have here three variables:
                #    'set_name' which is the new name for the physical interface(WANLTE)
                #    'ifname' which is the vppsb interface name (vpp1).
                #    'old_ifname' which is the original lte interface name (wwan0)
                #
                # 'ethernets' at this point looks:
                # {
                #   'eno1': ...,
                #   'eno2': ...,
                #   'vpp1': {
                #       'addresses': ['10.95.246.39/28'],
                #       'dhcp4': False,
                #       'mtu': 1500,
                #       'nameservers': {'addresses': ['91.135.104.8', '91.135.102.8']},
                #       'routes': [{'metric': 150, 'to': '0.0.0.0/0', 'via': '10.95.246.40'}]},
                #    'wwan0': {'match': {'macaddress': 'ba:2a:be:44:38:e8'}, 'set-name': 'WANLTE'}
                # }
                # So we need to clear the ip configuration for vpp1, and keep the the set-name on the wwan0

        _write_to_netplan_file(fname_run, config)

        # Remove default route from ip table because Netplan is not doing it.
        # Note we do that directly by 'ip route del' command
        # and not relay on 'netplan apply', as in last case VPPSB does not handle
        # properly kernel NETLINK messsages and does not update VPP FIB.
        if type.upper() == 'WAN':
            (old_gw,old_ifname,_,_,old_metric) = fwutils.get_default_route(ifname)
            if (is_add == False) or (old_ifname and ((gw != old_gw) or (metric != old_metric))):
                fwutils.remove_linux_default_route(ifname)

        fwutils.netplan_apply('add_remove_netplan_interface')

        if is_add and set_name and set_name is not ifname and not is_lte:
            # To understand the following code, it is necessary to understand the following two principles:
            #
            # 1. To apply the set-name,
            #   the interface name in netplan must be the *current* interface name in Linux.
            #   The "match" section is not enough for changing the interface name.
            #
            #   Assuming we have vpp0 in Linux and we want to change it to eth2 -
            #     The following netplan config will work:
            #       vpp0:
            #         addresses: [172.16.55.1/24]
            #         dhcp4: false
            #         match: {macaddress: '00:e0:ed:8f:73:94'}
            #         mtu: 1400
            #         set-name: eth2
            #
            #     The following netplan config will not work:
            #       eth2:
            #         addresses: [172.16.55.1/24]
            #         dhcp4: false
            #         match: {macaddress: '00:e0:ed:8f:73:94'}
            #         mtu: 1400
            #         set-name: eth2
            #
            # 2. When the agent enables tap-inject in the start-router process, the vppsb creates the interface with the vppX name.
            #   The vppsb doesn't know at this point about the set-name.
            #
            # Following the example above, when the router starts -
            #   the "ifname" (taken from fwutils.dev_id_to_tap(dev_id)) is vpp0 and the set-name is eth2.
            #
            # The following netplan file is created:
            #   vpp0:
            #     addresses: [172.16.55.1/24]
            #     dhcp4: false
            #     match: {macaddress: '00:e0:ed:8f:73:94'}
            #     mtu: 1400
            #     set-name: eth2
            #
            # At this point, after "netplan apply", the interface name is changed to eth2, and vpp0 is no longer exists.
            # So, the generated netplan config for this interface is under non-exists interface name.
            #
            # This situation causes a future problem:
            # Once `modify-interface` arrives, the `dev_id_to_tap()` will return `eth2` and not `vpp0`.
            # This function will add the config under `eth2` interface, without removing the `vpp0` which no longer exists.
            # As a result, the netplan file contains the same interface twice:
            #   vpp0:
            #     addresses: [172.16.55.1/24]
            #     dhcp4: false
            #     match: {macaddress: '00:e0:ed:8f:73:94'}
            #     mtu: 1400
            #     set-name: eth2
            #   eth2:
            #     addresses: [172.16.55.1/24]
            #     dhcp4: false
            #     match: {macaddress: '00:e0:ed:8f:73:94'}
            #     mtu: 1400
            #     set-name: eth2
            #
            # Hence, immediately after the set-name applied,
            # we are changing the default vppsb name (vpp0) with the applied set-name interface (eth2) name.
            # No need to call netplan apply now.
            #
            config['network']['ethernets'][set_name] = config['network']['ethernets'].pop(ifname)
            _write_to_netplan_file(fname_run, config)

            ifname = set_name

        # In some cases, the interface remains in a down state even after calling netplan apply.
        # This has been observed multiple times in cloud-based virtual setups, often due to a conflict: "Device or resource busy".
        # Running netplan apply again resolves the issue.
        # Therefore, check if the interface is up; if not, retry netplan apply.
        if is_add:
            is_ifc_down = fwutils.vpp_get_interface_status(dev_id=dev_id, print_exception_on_error=False).get('admin') == 'down'
            if is_ifc_down:
                fwglobals.log.warning(f"add_remove_netplan_interface(): {ifname} status is down")
                time.sleep(5)  # give Linux a moment to release the lock
                fwutils.netplan_apply('add_remove_netplan_interface')

        # Ensure that IP was assigned by system before further configurations.
        # Note, we give 10 seconds to cover DHCP case.
        # That covers static address case as well, that might require a second
        # or two for linux to update interfaces.
        #
        if is_add and (ip or dhcp == "yes"):
            if_addr = fwutils.get_interface_address(ifname, log=False)
            if not if_addr and fwutils.get_interface_linux_carrier_value(ifname) == '1':
                for _ in range(10):
                    time.sleep(1)
                    if_addr = fwutils.get_interface_address(ifname, log=False)
                    if if_addr:
                        fwglobals.log.debug(f"{dev_id}: got address {if_addr}")
                        break
                if not if_addr and dhcp != 'yes':
                    err_str = f"{dev_id}: static address {ip} was not assigned by kernel"
                    _revert_netplan_file(fname_run, old_config, err_str)
                    return (False, err_str)

        if dev_id:
            _update_cache(is_add, dev_id, ifname)

    except Exception as e:
        err_str = "add_remove_netplan_interface failed: dev_id: %s, file: %s, error: %s"\
              % (dev_id, fname_run, str(e))
        fwglobals.log.error(err_str)
        _dump_netplan_file(fname_run)
        return (False, err_str)

    return (True, None)

_netplan_yaml_cache = fw_os_utils.FwYamlFileCache()

def is_interface_dhcp(if_name):
    files = glob.glob("/etc/netplan/*.yaml") + \
            glob.glob("/lib/netplan/*.yaml") + \
            glob.glob("/run/netplan/*.yaml")

    _netplan_yaml_cache.forget_except(files)   # forget removed files

    for fname in files:
        config = _netplan_yaml_cache.load(fname)   # IMPORTANT: don't modify the returned object!

        if config is None:
            continue

        network = config.get('network')
        if not network:
            continue

        if fwutils.is_vlan_interface(if_name=if_name):
            vlans = network.get('vlans')
            if not vlans:
                continue

            if if_name in vlans:
                interface = vlans[if_name]
                if interface.get('dhcp4'):
                    return 'yes'

            continue

        if not 'ethernets' in network:
            continue
        ethernets = network['ethernets']

        if if_name in ethernets:
            interface = ethernets[if_name]
            if interface.get('dhcp4'):
                return 'yes'
    return 'no'

def check_interface_exist(if_name):
    files = netplan_get_filepaths()

    for fname in files:
        config = None
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if not config:
                continue
            interface = config.get('network',{}).get('ethernets',{}).get(if_name)
            if interface:
                return fname

    return None

def remove_interface(if_name):
    files = netplan_get_filepaths()

    for fname in files:
        config = None
        with open(fname, 'r') as stream:
            config = yaml.safe_load(stream)
            if config is None:
                continue
            if 'network' in config:
                network = config['network']
                if 'ethernets' in network:
                    ethernets = network['ethernets']
                    if if_name in ethernets:
                        removed_section = copy.deepcopy(ethernets[if_name])
                        del ethernets[if_name]
                        with open(fname, 'w', opener=_secure_opener) as file_stream:
                            yaml.dump(config, file_stream)
                        fwutils.netplan_apply('remove_interface_netplan')
                        return (fname, removed_section)
    return ('', '')

def add_interface(if_name, fname, netplan_section):
    config = None
    with open(fname, 'r') as stream:
        config = yaml.safe_load(stream)
        if 'network' in config:
            network = config['network']
            if 'ethernets' in network:
                ethernets = network['ethernets']
                ethernets[if_name] = netplan_section
                with open(fname, 'w', opener=_secure_opener) as file_stream:
                    yaml.dump(config, file_stream)
                fwutils.netplan_apply('add_interface_netplan')

def create_baseline_if_not_exist(fname):
    if 'baseline' in fname:
        return fname

    fname_baseline = fname.replace('yaml', 'baseline.yaml')
    os.system(f'cp {fname} {fname}.{edge_ui_backup_extension}')
    os.system(f'mv {fname} {fname_baseline}')
    return fname_baseline


def _set_netplan_section_vlan(config_section, vlan_id, parent_dev_id):
    ifname = fwutils.dev_id_to_tap(parent_dev_id)
    config_section['id'] = vlan_id
    config_section['link'] = ifname
    return config_section

def _update_cache(is_add, dev_id, ifname):
    # On interface adding or removal update caches interface related caches.
    #
    dev_id_full = fwutils.dev_id_to_full(dev_id)

    # Remove dev-id-to-vpp-if-name and vpp-if-name-to-dev-id cached
    # values for this dev id if the interface is removed from system.
    #
    if is_add == False:
        vpp_if_name = fwglobals.g.cache.dev_id_to_vpp_if_name.get(dev_id_full)
        if vpp_if_name:
            del fwglobals.g.cache.dev_id_to_vpp_if_name[dev_id_full]
            del fwglobals.g.cache.vpp_if_name_to_dev_id[vpp_if_name]
    fwutils.clear_vpp_if_name_negative_cache()

    # Remove dev-id-to-tap cached value for this dev id, as netplan might change
    # interface name (see 'set-name' netplan option).
    # As well re-initialize the interface name by dev id.
    # Note 'dev_id' is None for tap-inject (vppX) of tapcli-X interfaces used for LTE/WiFi devices.
    #
    if is_add == True:
        fwutils.set_dev_id_to_tap(dev_id, ifname)
        fwglobals.log.debug("Interface name in cache is %s, dev_id %s" % (ifname, dev_id_full))
    else:
        fwutils.unset_dev_id_to_tap(dev_id)

def add_remove_netplan_vlan(is_add, dev_id, ip, gw, metric, dhcp, type,  dnsServers, dnsDomains):
    '''Add vlan section like below into Netplan file.
        vlans:
         eth1.10:
           dhcp4: true
           id: '10'
           link: eth1
    '''
    type = type.upper()

    fwglobals.log.debug(
        "add_remove_netplan_vlan: is_add=%d, dev_id=%s, ip=%s, gw=%s, metric=%d, dhcp=%s, type=%s" % \
        (is_add, dev_id, ip, gw, metric, dhcp, type))

    fo_metric = get_wan_failover_metric(metric, dev_id=dev_id)
    if fo_metric != metric:
        fwglobals.log.debug(
            "add_remove_netplan_vlan: dev_id=%s, use wan failover metric %d" % (dev_id, fo_metric))
        metric = fo_metric

    ifname = fwutils.dev_id_to_tap(dev_id)
    if not ifname:
        err_str = "add_remove_netplan_vlan: %s was not found" % dev_id
        fwglobals.log.error(err_str)
        return (False, err_str)

    parent_dev_id, vlan_id = fwutils.dev_id_parse_vlan(dev_id)

    entry = fwglobals.g.NETPLAN_FILES.get(parent_dev_id, None)
    if entry:
        fname_run = entry.get('fname').replace('yaml', f'{active_router_fn_extension}.yaml')
    else:
        fname_run = fwglobals.g.NETPLAN_FILE
    _add_netplan_file(fname_run)

    try:
        with open(fname_run, 'r') as stream:
            config = yaml.safe_load(stream)
            network = config['network']
            network['renderer'] = 'networkd'

        if 'vlans' not in network:
            network['vlans'] = {}

        vlans = network['vlans']

        config_section = {}
        config_section = _set_netplan_section_vlan(config_section, vlan_id, parent_dev_id)
        config_section = _set_netplan_section_dhcp(config_section, dhcp, type, metric, ip, gw, dnsServers, dnsDomains)

        if is_add == True:
            vlans[ifname] = config_section
        else:
            if ifname in vlans:
                del vlans[ifname]

        _write_to_netplan_file(fname_run, config)

        # Remove default route from ip table because Netplan is not doing it.
        if not is_add and type == 'WAN':
            fwutils.remove_linux_default_route(ifname)

        fwutils.netplan_apply('add_remove_netplan_vlan')

        if dev_id:
            _update_cache(is_add, dev_id, ifname)

    except Exception as e:
        err_str = "add_remove_netplan_vlan failed: dev_id: %s, file: %s, error: %s"\
              % (dev_id, fname_run, str(e))
        fwglobals.log.error(err_str)
        _dump_netplan_file(fname_run)
        return (False, err_str)

    return (True, None)

def save_dev_id_to_kernel_mapping():
    dev_id_to_kernel_name = fwutils.get_kernel_interfaces()
    # remove interfaces that were renamed by 'set-name' directive in yaml, we don't support them
    files = load_netplan_filenames(get_only=True)
    for devices in files.values():
        for dev in devices:
            if dev['set-name'] and dev['dev_id'] in dev_id_to_kernel_name:
                fwglobals.log.debug(f"save_dev_id_to_kernel_mapping(): skip {dev}: set-name is not supported")
                del dev_id_to_kernel_name[dev['dev_id']]
    # store built mapping onto disk to handle flow where agent daemon is restarted while VPP is on air
    fwglobals.g.db['dev_id_to_kernel_name'] = dev_id_to_kernel_name

def generate_recovery_netplan():
    '''Generates flexiwan.recovery.yaml file that should ensure internet connectivity.
    That file represents merge of all currently active *.yaml-s.
    In addition, and this is the point, it has modified configuration of WAN interfaces.
    The modification overrides WAN interfaces to have static IP addresses and GW-s
    currently set in the kernel.
        The WAN interfaces are determined base on the default route rules.
        To ensure internet connectivity, this function should be executed
    when networking is operational and the internet is accessible. For instance,
    it can be invoked immediately after successful establishing a connection to flexiManage.
        Note, we merge all currently active *.yaml-s in order to have LAN and unassigned
    interfaces configured in the recovery yaml.
    '''
    # ensure no stale file in system if this function fails for any reason
    os.system(f'rm -f {fwglobals.g.NETPLAN_RECOVERY_FILE_STANDBY}')

    # Fetch names of interfaces in kernel.
    # If VPP does not run at the moment, we take them from Linux,
    # if VPP does run - from persistent cache (DB file on disk).
    #
    if fwglobals.g.router_api.state_is_stopped():
        save_dev_id_to_kernel_mapping()
    dev_id_to_kernel_name = fwglobals.g.db['dev_id_to_kernel_name']

    # Find WAN interfaces out of default route rules and build netplan configurations for them.
    #
    wan_devices      = {}
    linux_routes     = fwroutes.FwLinuxRoutes(prefix='0.0.0.0/0')
    linux_interfaces = fwutils.get_linux_interfaces()
    for route in linux_routes.values():
        try:
            linux_dev = dev_id_to_kernel_name.get(route.dev_id)
            if not linux_dev:
                fwglobals.log.debug(f"generate_recovery_netplan: skip {route}: kernel name not found")
                continue
            if fwutils.is_non_dpdk_interface(route.dev_id) or fwpppoe.is_pppoe_interface(dev_id=route.dev_id):
                fwglobals.log.debug(f"generate_recovery_netplan: skip {route}: non-dpdk devices are not supported")
                continue
            if linux_dev in wan_devices:
                fwglobals.log.warning(f"multi-hop routes are not supported")
                continue
            interface = linux_interfaces.get(route.dev_id)
            if not interface:
                raise Exception(f"interface {route.dev_id} is not in cache")
            if not interface.get('IPv4') or not interface.get('IPv4Mask'):
                raise Exception(f"generate_recovery_netplan: skip {route}: no address/len for interface {route.dev_id} in cache")
            address = f"{interface['IPv4']}/{interface['IPv4Mask']}"

            wan_devices.update({
                linux_dev: {
                    'dhcp4': False,
                    'addresses':  [ address ],
                    'nameservers': {
                        'addresses': interface.get('dns_servers') if interface.get('dns_servers') else fwglobals.g.DEFAULT_DNS_SERVERS
                    },
                    'routes': [
                        { 'to': 'default', 'via': route.via, 'metric': route.metric }
                    ]
                }
            })
        except Exception as _e:
            fwglobals.log.error(f"generate_recovery_netplan: skip {route}: {_e}")

    if not wan_devices:
        fwglobals.log.error(f"generate_recovery_netplan: no suitable WAN devices were found")
        return

    # Load all currently active *.yaml-s.
    #
    recovery_yaml = {
                        'network': {
                            'version':   2,
                            'renderer': 'networkd',
                            'ethernets': {}
                        }
                    }
    for fname in netplan_get_filepaths():
        with open(fname, 'r') as stream:
            current_yaml  = yaml.safe_load(stream)
            recovery_yaml = merge_netplan_yaml(recovery_yaml, current_yaml)

    # If VPP runs, we have to convert VPP tap names to kernel names in the yaml.
    # We don't support VLAN, WiFi, etc at the moment, so the final recovery yaml might
    # get unusable devices. Still, the basic configuration - LAN-s & WAN-s, should be OK.
    #
    if not fwglobals.g.router_api.state_is_stopped():  # handle both STARTED and STARTING states
        devices             = recovery_yaml['network']['ethernets']
        tap_to_kernel_names = fwutils.vpp_get_tap_inject_mapping_to_kernel_names()
        for dev_name in list(devices.keys()):
            if dev_name in tap_to_kernel_names:
                devices[tap_to_kernel_names[dev_name]] = devices.pop(dev_name)

    # Now add WAN interfaces that we built, while overriding existing configuration.
    #
    recovery_yaml['network']['ethernets'].update(wan_devices)

    # Finally dump configuration into flexiwan.yaml.recovery.
    #
    with open(fwglobals.g.NETPLAN_RECOVERY_FILE_STANDBY, 'w', opener=_secure_opener, encoding="utf-8") as fd:
        yaml.dump(recovery_yaml, fd)


def validate_recovery_netplan():
    '''Checks if the recovery netplan yaml can be applied.
       For example, ensures that the interface used by the netplan is plugged.

    :returns: None if the netplan is OK, error string otherwise.
    '''
    try:
        with open(fwglobals.g.NETPLAN_RECOVERY_FILE_STANDBY, 'r', encoding="utf-8") as stream:
            recover_yaml = yaml.load(stream, Loader=yaml.BaseLoader)
    except Exception as e:
        return f"failed to load {fwglobals.g.NETPLAN_RECOVERY_FILE_STANDBY}: {e}"

    interfaces = recover_yaml.get('network', {}).get('ethernets',{}).keys()
    for iface_name in interfaces:
        if fwutils.get_interface_linux_carrier_value(iface_name) == '1':
            return None  # we are OK - at least one available interface is enough
    return f"no plugged interfaces was found in {fwglobals.g.NETPLAN_RECOVERY_FILE_STANDBY} (found interfaces: {interfaces})"


def start_recovery_netplan():
    fwglobals.log.debug("start_recovery_netplan: replace all yaml-s with recovery one")
    for filepath in glob.glob("/etc/netplan/*.yaml"):
        shutil.move(filepath, f"{filepath}{fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT}")
    shutil.copy(fwglobals.g.NETPLAN_RECOVERY_FILE_STANDBY, fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE)
    fwutils.netplan_apply('start_recovery_netplan')


def stop_recovery_netplan():
    netplan_apply_required = False
    for filepath in glob.glob(f"/etc/netplan/*{fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT}"):
        original = filepath.split(fwglobals.g.NETPLAN_RECOVERY_BAD_FILE_EXT)[0]
        fwglobals.log.debug(f"stop_recovery_netplan: restore {filepath} into {original}")
        shutil.move(filepath, original)
        netplan_apply_required = True
    for filepath in glob.glob("/etc/netplan/*flexiwan*recovery*.yaml"):
        fwglobals.log.debug(f"stop_recovery_netplan: remove {filepath}")
        os.remove(filepath)
        netplan_apply_required = True
    if netplan_apply_required:
        fwutils.netplan_apply('stop_recovery_netplan')

def was_recovery_netplan_started():
    return os.path.exists(fwglobals.g.NETPLAN_RECOVERY_FILE_ACTIVE)

def merge_netplan_yaml(yaml1, yaml2):
    merged = yaml1  # add reuse_left=False parameter and copy() if you don't want to override
    for device_type in ['ethernets', 'wifis', 'bridges', 'modems']:
        devices = yaml2.get('network', {}).get(device_type, {})
        for dev_name, dev_config in devices.items():
            if device_type not in merged['network']:
                merged['network'][device_type] = {}
            merged['network'][device_type].update({dev_name: dev_config})
    return merged
