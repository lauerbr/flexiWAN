#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2024 flexiWAN Ltd.
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

import csv
import ipaddress
import json
import os
import shutil
import subprocess
import re
import tempfile

from netaddr import IPNetwork

import fwglobals

from fwobject import FwObject

class FwDhcpServer(FwObject):
    """This is object that encapsulates configuration of DHCP Server.
    """
    def __init__(self):
        FwObject.__init__(self)
        self.config = None

        self.default_config = {
            'Dhcp4': {
                'dhcp-ddns': {
                    'enable-updates': False
                },
                'lease-database': {
                    'type': 'memfile',
                    'persist': True,
                    'name': fwglobals.g.KEA_DHCP_LEASE_DB_FILE,
                    'lfc-interval': 3600
                },
                'interfaces-config': {
                    'interfaces': [ '*' ],
                    'dhcp-socket-type': 'raw'
                },
                'subnet4': [],
                'loggers': [{
                    "name": "kea-dhcp4",
                    "output_options": [{
                        "output": fwglobals.g.DHCP_LOG_FILE,
                        "maxsize": 10240000,
                        "maxver": 1
                    }],
                    "severity": "INFO"
                }],
                'expired-leases-processing': {
                    'reclaim-timer-wait-time': 10,
                    'flush-reclaimed-timer-wait-time': 25,
                    'hold-reclaimed-time': 3600,
                    'max-reclaim-leases': 100,
                    'max-reclaim-time': 250,
                    'unwarned-reclaim-cycles': 5
                },
                'renew-timer': 900,
                'rebind-timer': 1800,
                'valid-lifetime': 3600,
                'sanity-checks': {
                    'lease-checks': 'fix-del'
                },
            }
        }

        # Initialize an empty set to store IPs for which DHCP RELEASE messages will be dropped
        self.ips_to_drop_release = set()

        self.load_config_from_file()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        return

    def start(self):
        cmd = 'systemctl start kea-dhcp4-server'
        self.log.debug(cmd)
        try:
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            self.log.error(f"start() failed: {str(e)}")
            raise e

    def stop(self):
        cmd = 'systemctl stop kea-dhcp4-server'
        self.log.debug(cmd)
        try:
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            self.log.error(f"stop() failed: {str(e)}")
            raise e

    def restart(self):
        cmd = 'systemctl restart kea-dhcp4-server'
        self.log.debug(cmd)
        try:
            subprocess.check_call(cmd, shell=True)
        except Exception as e:
            self.log.error(f"restart() failed: {str(e)}")
            raise e

    def _validate_config(self):
        # Use private temporary file (mkstemp creates 0600 file) instead of fixed /tmp path
        fd, tmp_file = tempfile.mkstemp(prefix='kea-dhcp4.', suffix='.tmp')
        with os.fdopen(fd, 'w+') as f:
            json.dump(self.config, f, indent=2)

        try:
            subprocess.check_output(['kea-dhcp4', '-t', tmp_file],  stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            err = str(e.output.decode().strip())
            self.log.error(f"_validate_config(): {err}")
            raise Exception(err)
        except Exception as e:
            self.log.error(f"_validate_config(): {str(e)}")
            raise e
        finally:
            os.remove(tmp_file)

    def _write_config_file(self, validate=True):
        if validate:
            self._validate_config()

        with open(fwglobals.g.KEA_DHCP_CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)

    def reset_config(self, assigned_linux_interfaces):
        try:
            # stop DHCP server service with Linux config on start router
            self.stop()

            if not os.path.exists(fwglobals.g.KEA_DHCP_CONFIG_FILE_BACKUP):
                shutil.copyfile(fwglobals.g.KEA_DHCP_CONFIG_FILE, fwglobals.g.KEA_DHCP_CONFIG_FILE_BACKUP)

            # keep the original Linux config but remove the assigned interface related config
            self.load_config_from_file()

            # remove assigned interfaces from the file.
            # if user configured "*" in Linux config file, don't touch it
            int_configs = self.config['Dhcp4']['interfaces-config']['interfaces']
            if not '*' in int_configs:
                for ifc in assigned_linux_interfaces:
                    if ifc in int_configs:
                        int_configs.remove(ifc)

            self._write_config_file()
        except Exception as e:
            self.log.error(f"reset_config: {str(e)}")

    def restore_config(self):
        try:
            if os.path.exists(fwglobals.g.KEA_DHCP_CONFIG_FILE_BACKUP):
                shutil.copyfile(fwglobals.g.KEA_DHCP_CONFIG_FILE_BACKUP, fwglobals.g.KEA_DHCP_CONFIG_FILE)
                os.remove(fwglobals.g.KEA_DHCP_CONFIG_FILE_BACKUP)

            # restart DHCP server service with Linux config
            self.restart()
        except Exception as e:
            self.log.error(f"restore_config: {str(e)}")

    def load_config_from_file(self):
        try:
            if os.path.exists(fwglobals.g.KEA_DHCP_CONFIG_FILE):
                with open(fwglobals.g.KEA_DHCP_CONFIG_FILE, 'r') as json_file:
                    self.config = json.load(json_file)
            else:
                self.config = {}

            # keep some Linux config or set our default
            self.config.setdefault('Dhcp4', {})
            self.config['Dhcp4'].setdefault('lease-database', self.default_config['Dhcp4']['lease-database'])
            self.config['Dhcp4'].setdefault('loggers', self.default_config['Dhcp4']['loggers'])
            self.config['Dhcp4'].setdefault('interfaces-config', self.default_config['Dhcp4']['interfaces-config'])
            self.config['Dhcp4'].setdefault('subnet4', self.default_config['Dhcp4']['subnet4'])
            self.config['Dhcp4'].setdefault('dhcp-ddns', self.default_config['Dhcp4']['dhcp-ddns'])
            self.config['Dhcp4'].setdefault('sanity-checks', self.default_config['Dhcp4']['sanity-checks'])

            # When the agent loads, retrieve and store any existing IPs (used to drop DHCP RELEASE messages)
            # from the DROP client-class in the configuration into memory.
            for client_class in self.config['Dhcp4'].get('client-classes', []):
                if client_class.get('name') == 'DROP':
                    # Extract IP addresses from the 'test' string using regex and update the ips_to_drop_release set.
                    matched_ips = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', client_class['test'])
                    self.ips_to_drop_release.update(matched_ips)
                    break

        except ValueError:
            # Kea's original (with examples) file may not be a valid JSON,
            # so we use the default config if parsing fails.
            self.config = dict(self.default_config)
        except Exception as e:
            self.log.error(f"load_config_from_file: {str(e)}")
            raise e

    def _build_config_options(self, options, ifc_ip, dns):
        options_conf = []
        router_option = None

        for option in options:
            name = option['option']
            value = option['value']
            options_conf.append({ 'name': name, 'data': value })
            if name == 'routers':
                router_option = value

        # if user didn't provide a gateway, we put the interface ip
        if not router_option:
            options_conf.append({ 'name': 'routers', 'data': ifc_ip })
            router_option = ifc_ip

        if dns:
            options_conf.append({
                'name': 'domain-name-servers',
                'data': ", ".join(dns)
            })

        return options_conf, router_option

    def _build_config_reservations(self, static_assign):
        reservations_conf = []
        for static in static_assign:
            reservation_conf = {
                'hw-address': static.get('mac'),
                'hostname': static.get('host'),
                'ip-address': static.get('ipv4')
            }

            use_host_name_as_dhcp_option = static.get('useHostNameAsDhcpOption')
            if use_host_name_as_dhcp_option:
                reservation_conf['option-data'] = [{
                    'name': 'host-name',
                    'data': static.get('host')
                }]

            reservations_conf.append(reservation_conf)
        return reservations_conf

    def _get_missing_or_next_id(self):
        max_id = 0
        id_set = set()

        for subnet in list(self.config['Dhcp4']['subnet4']):
            id_set.add(subnet['id'])
            max_id = max(max_id, subnet['id'])

        # find missing numbers
        for i in range(1, max_id):
            if i not in id_set:
                return i

        # next id
        return max_id + 1

    def add(self, dev_id, range_start, range_end, dns, static_assign, options, max_lease_time, default_lease_time, preserve_ip=False):
        """Adds an interface to the /etc/kea/kea-dhcp4.conf configuration file in order to use dhcp server on it.
        """
        interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
        if not interfaces:
            return (False, f"add: {dev_id} was not found")

        address = IPNetwork(interfaces[0]['addr'])
        ifc_ip = str(address.ip)
        network = str(address.network)
        prefixlen = str(address.prefixlen)

        options_conf, routers_option = self._build_config_options(options, ifc_ip, dns)
        reservations_conf            = self._build_config_reservations(static_assign)

        routers_list = routers_option.split(',')

        # remove current config for the subnet if exists
        for subnet in list(self.config['Dhcp4']['subnet4']):
            if IPNetwork(subnet['subnet']) in address:
                self.config['Dhcp4']['subnet4'].remove(subnet)

        subnet_config = {
            'id': self._get_missing_or_next_id(),
            'subnet': f'{network}/{prefixlen}',
            'pools': self._split_ip_range(range_start, range_end, routers_list),
            'option-data': options_conf,
            'reservations': reservations_conf
        }

        if default_lease_time:
            subnet_config['valid-lifetime'] = default_lease_time
        if max_lease_time:
            subnet_config['max-valid-lifetime'] = max_lease_time


        self.config['Dhcp4']['subnet4'].append(subnet_config)

        # add interface to the listen interfaces
        int_configs = self.config['Dhcp4']['interfaces-config']['interfaces']
        if not '*' in int_configs:
            self.config['Dhcp4']['interfaces-config'] = ['*']

        if preserve_ip:
            self.ips_to_drop_release.update(map(str.strip, routers_list))
            self._configure_drop_class()

        # validate and write
        self._write_config_file()

        # Update persistent cache with DHCPD interface
        #
        router_api_db = fwglobals.g.db['router_api'] # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        router_api_db['dhcpd']['interfaces'].update({dev_id: None})
        fwglobals.g.db['router_api'] = router_api_db

    def _configure_drop_class(self):
        """
        This function configures the DROP client-class in the DHCP server configuration.
        It creates (or updates) a client-class named 'DROP' that matches the IPs in the
        'ips_to_drop_release' set. The class is used to drop DHCP RELEASE messages for the
        specified IPs, preventing the DHCP server from releasing them.
        """
        client_classes = self.config['Dhcp4'].setdefault('client-classes', [])
        drop_class = next((cc for cc in client_classes if cc.get('name') == 'DROP'), None)

        # If there are no IPs to drop, remove the DROP class (if it exists). Keeping it will match everything
        if not self.ips_to_drop_release:
            if drop_class is not None:
                client_classes.remove(drop_class)

            # kea does not allow empty list of "client-classes"
            if len(client_classes) == 0:
                del self.config['Dhcp4']['client-classes']

            return

        if drop_class is None:
            drop_class = {'name': 'DROP', 'test': ''}
            client_classes.append(drop_class)

        conditions = [f"pkt.dst == {ip}" for ip in self.ips_to_drop_release]
        if len(conditions) == 1:
            test_str = f"pkt4.msgtype == 7 and {conditions[0]}"
        else:
            test_str = f"pkt4.msgtype == 7 and ({' or '.join(conditions)})"

        drop_class['test'] = test_str

    def remove(self, dev_id):
        interfaces = fwglobals.g.router_cfg.get_interfaces(dev_id=dev_id)
        if not interfaces:
            return (True, f"{dev_id} was not found")

        address = IPNetwork(interfaces[0]['addr'])

        for subnet in list(self.config['Dhcp4']['subnet4']):
            if IPNetwork(subnet['subnet']) in address:
                # remove the IPs from the list of IPs to drop release
                for option in subnet.get('option-data', []):
                    if option['name'] != 'routers':
                        continue

                    routers_list = option['data'].split(',')
                    for router in routers_list:
                        self.ips_to_drop_release.discard(router.strip())
                    break

                self.config['Dhcp4']['subnet4'].remove(subnet)
                break

        self._configure_drop_class()

        self._write_config_file()

        router_api_db = fwglobals.g.db['router_api'] # SqlDict can't handle in-memory modifications, so we have to replace whole top level dict
        if dev_id in router_api_db['dhcpd']['interfaces']:
            del router_api_db['dhcpd']['interfaces'][dev_id]
            fwglobals.g.db['router_api'] = router_api_db

    def _split_ip_range(self, range_start, range_end, exclude_ips):
        """Calculate and return string contains the DHCP "range" option.

        DHCP doesn't exclude the IPs configured as routers from the IP pool.
        It may offer clients the router ip itself.
        The function removes the router IPs from the range configured
        by the user by splitting the range into multiple ranges.

        :param range_start:     String of the first ip of the range (172.16.1.100)
        :param range_end:       String of the last ip of the range (172.16.1.200)
        :param exclude_ips:     List contains the IPs to exclude

        :returns: list of ranges

        """
        start_ip = ipaddress.ip_address(range_start)
        end_ip = ipaddress.ip_address(range_end)
        ranges = [[start_ip, end_ip]]

        # convert the excluded IPs to ip_address objects.
        # we also sort the list as the order is mandatory for below logic
        exclude_ips = sorted(list(map(lambda x: ipaddress.ip_address(x.strip()), exclude_ips)))

        for exclude_ip in exclude_ips:
            range_start_ip, range_end_ip = ranges[-1]

            if exclude_ip < range_start_ip or exclude_ip > range_end_ip:
                continue

            if exclude_ip == range_start_ip:
                ranges[-1][0] = exclude_ip + 1
                continue

            if exclude_ip == range_end_ip:
                ranges[-1][1] = exclude_ip - 1
                continue

            ranges[-1][1] = exclude_ip - 1
            ranges.append([exclude_ip + 1, range_end_ip])

        ranges = list(map(lambda range_arr: { 'pool': f'{range_arr[0]}-{range_arr[1]}' }, ranges))
        return ranges

    def get_leases(self):
        """Get leases from the lease database.
        """
        leases = {}
        try:
            files = [
                fwglobals.g.KEA_DHCP_LEASE_DB_FILE + '.2', # start with the second to prioritize the latest
                fwglobals.g.KEA_DHCP_LEASE_DB_FILE
            ]

            for file in files:
                if not os.path.exists(file):
                    continue

                with open(file) as csv_file:
                    rows = csv.DictReader(csv_file)
                    # latest_leases = {} #"rows" might contain multiple entries for same mac address. Only the latest is the updated
                    for row in rows:
                        mac = row.get('hwaddr', '')
                        leases[mac] = {
                            'address':          row.get('address', ''),
                            'hwaddr':           mac,
                            'client_id':        row.get('client_id', ''),
                            'valid_lifetime':   row.get('valid_lifetime', ''),
                            'expire':           row.get('expire', ''),
                            'subnet_id':        row.get('subnet_id', ''),
                            'fqdn_fwd':         row.get('fqdn_fwd', ''),
                            'fqdn_rev':         row.get('fqdn_rev', ''),
                            'hostname':         row.get('hostname', ''),
                            'state':            row.get('state', ''),
                            'user_context':     row.get('user_context'),
                            'active':           row.get('valid_lifetime', '') != '0'
                        }
        except Exception as e:
            self.log.error(f"get_leases() failed: {str(e)}")

        return list(leases.values())


def restore_config_safe():
    '''This function calls a function within dhcp_server even if the agent object is not initialized
    '''
    # when calling this function from fwdump, there is no "g" in fwglobals
    if hasattr(fwglobals.g, 'dhcp_server'):
        return fwglobals.g.dhcp_server.restore_config()

    with FwDhcpServer() as dhcp_server:
        return dhcp_server.restore_config()