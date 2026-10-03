#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
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

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from os.path import exists

from netaddr import IPNetwork

current_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(current_dir)
from application_cfg import config as cfg

applications_dir = os.path.join(current_dir, "../")
sys.path.append(applications_dir)
from applications.fwapplication_interface import FwApplicationInterface

agent_dir = os.path.join(applications_dir, "../")
sys.path.append(agent_dir)
import fw_os_utils
import fw_input_validation

def _apt_key_add_from_url(url):
    """Download apt key over HTTPS into temporary file and add it to apt.
    It replaces the 'wget -O - <url> | apt-key add -' pipe, so failure
    to download is not masked by the pipe.
    """
    if not url.startswith('https://'):
        raise Exception(f'refuse to fetch apt key over non-HTTPS URL {url}')
    tmp_dir = tempfile.mkdtemp()
    try:
        key_file = os.path.join(tmp_dir, 'repo.gpg')
        subprocess.check_call(['wget', '-q', '--https-only', '-O', key_file, url])
        subprocess.check_call(['apt-key', 'add', key_file], stdout=subprocess.DEVNULL)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

class Application(FwApplicationInterface):

    def install(self, params):
        """Install Remote VPN server on host.

        :param params - remote vpn parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            installed = os.popen("dpkg -l | grep -E '^ii' | grep openvpn").read()
            dir_is_empty = exists('/etc/openvpn/server') and len(os.listdir('/etc/openvpn/server')) == 0
            if installed and not dir_is_empty:
                return

            os.system('mkdir -p /etc/openvpn/server')

            self._create_symbol_links()

            distro = os.popen('lsb_release -cs').read().strip()
            try:
                _apt_key_add_from_url('https://swupdate.openvpn.net/repos/repo-public.gpg')
                fw_os_utils.run_linux_commands( [
                    f'echo "deb http://build.openvpn.net/debian/openvpn/release/2.5 {distro} main" > /etc/apt/sources.list.d/openvpn-aptrepo.list',
                ])
            except Exception as e:
                self.log.error(f"failed to install from openvpn repo. trying another way: {str(e)}")
                _apt_key_add_from_url('https://vpnrepo.flexiwan.com/debian/openvpn/release/2.5/pubkey.gpg')
                fw_os_utils.run_linux_commands([
                    f'echo "deb https://vpnrepo.flexiwan.com/debian/openvpn/release/2.5/ {distro} main" > /etc/apt/sources.list.d/openvpn-aptrepo.list'
                ]
            )

            fw_os_utils.run_linux_commands([
                'apt install -y ca-certificates && apt-get update && apt-get install -y openvpn',
            ])
            self.log.info(f'application installed successfully')

        except Exception as e:
            self.log.error(f"install(): {str(e)}")
            # call uninstall function to revert the installation
            self.uninstall()
            raise e

    def _openvpn_pid(self):
        return fw_os_utils.pid_of('openvpn')

    def configure(self, params):
        """Configure Open VPN server on host.

        :param params: params - open vpn parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            self.log.info(f"application configurations: {str(cfg)}")

            # Write certificates and keys from Python and not by 'echo' shell
            # command, as the latter enables shell injection and exposes
            # the private keys in the process list. Keys are readable by root only.
            #
            files = [
                ('/etc/openvpn/server/ca.crt',     params['caCrt'],     0o644),
                ('/etc/openvpn/server/server.key', params['serverKey'], 0o600),
                ('/etc/openvpn/server/server.crt', params['serverCrt'], 0o644),
                ('/etc/openvpn/server/tc.key',     params['tlsKey'],    0o600),
                ('/etc/openvpn/server/dh.pem',     params['dhKey'],     0o644),
            ]
            for filename, content, mode in files:
                if not isinstance(content, str):
                    raise Exception(f'invalid content for {filename}')
                fw_os_utils.write_private_file(filename, content + '\n', mode=mode)

            self._configure_server_file(params)

            self.start(restart=True)

        except Exception as e:
            self.log.error(f"configure({params}): {str(e)}")
            raise e

    def _create_symbol_links(self, skip_if_exist=False):
        """Create symbolic links for the OpenVPN scripts.
        :param skip_if_exist: if True, skip creating the symbolic link if it already exists
        :returns: None
        """
        path = os.path.dirname(os.path.realpath(__file__))
        files_map = {
            f'{path}/scripts/auth.py':           '/etc/openvpn/server/auth-script.py',
            f'{path}/scripts/up.py':             '/etc/openvpn/server/up-script.py',
            f'{path}/scripts/down.py':           '/etc/openvpn/server/down-script.py',
            f'{path}/scripts/client-connect.py': '/etc/openvpn/server/client-connect.py',
            f'{path}/scripts/scripts_logger.py': '/etc/openvpn/server/scripts_logger.py',
            f'{path}/scripts/script_utils.py':   '/etc/openvpn/server/script_utils.py',
            f'{path}/application_cfg.py':        '/etc/openvpn/server/application_cfg.py',
        }

        commands = []
        for src, dst in files_map.items():
            # Create a symlink and ensure the target is executable
            cmd = f'ln -sf {src} {dst} && chmod +x {dst}'

            if skip_if_exist:
                # Only run if the file is not a symlink or not executable
                # "|| true" ensures the entire line doesn't fail if the condition is not met
                # since run_linux_commands raises on failure
                conditional_cmd = f'([ ! -L {dst} ] || [ ! -x {dst} ]) && {cmd} || true'
                commands.append(conditional_cmd)
            else:
                commands.append(cmd)

        fw_os_utils.run_linux_commands(commands)


    def uninstall(self, files_only=False):
        """Remove Open VPN server from host.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            self.stop()

            commands = ['rm -rf /etc/openvpn/server/*']
            if not files_only:
                commands.append('apt-get remove -y openvpn')

            fw_os_utils.run_linux_commands(commands)

        except Exception as e:
            self.log.error(f"uninstall(): {str(e)}")
            raise e

    def _validate_server_params(self, params):
        """Validate parameters that are written into OpenVPN server.conf.
        Every line of server.conf is an OpenVPN directive, so newlines
        (e.g. injection of 'up <script>' directive) and quotes must be rejected.
        """
        fw_input_validation.ensure_int(params.get("port", "1194"), 'port', 1, 65535)
        if params.get("connections") is not None:
            fw_input_validation.ensure_int(params.get("connections"), 'connections', 1, 1000000)
        keepalive = params.get("keepalive", "10 20")
        if not isinstance(keepalive, str) or not re.fullmatch(r'[0-9]+ +[0-9]+', keepalive):
            raise Exception(f'invalid keepalive {keepalive!r}')
        fw_input_validation.ensure_int(params.get("vpnTmpTokenTime", "43200"), 'vpnTmpTokenTime', 0, 100000000)
        for url in params.get('vpnPortalServer', []):
            if not fw_input_validation.is_safe_string(url, forbidden='"\'`$\\ ,#;') or not url:
                raise Exception(f'invalid vpnPortalServer {url!r}')
        for dns_ip in params.get('dnsIps', []):
            fw_input_validation.ensure_ip(dns_ip, 'DNS server')
        for name in params.get('dnsDomains', []):
            if not fw_input_validation.is_valid_fqdn(name):
                raise Exception(f'invalid DNS domain {name!r}')

    def _configure_server_file(self, params):
        try:
            self._validate_server_params(params)

            ip = IPNetwork(params['vpnNetwork'])

            vpn_portal_urls = params.get('vpnPortalServer', [])

            commands = [
                # Which TCP/UDP port should OpenVPN listen on?
                f'port {params.get("port", "1194")}',

                # TCP or UDP server?
                'proto udp',

                # set dev (NIC) name
                f'dev {cfg["openvpn_interface_name"]}',

                # use dev tun
                'dev-type tun',

                # SSL/TLS root certificate
                'ca /etc/openvpn/server/ca.crt',
                'cert /etc/openvpn/server/server.crt',
                'key /etc/openvpn/server/server.key',

                # Diffie hellman parameters.
                'dh /etc/openvpn/server/dh.pem',

                # Select a cryptographic cipher.
                'auth SHA512',

                # The server and each client must have a copy of this key
                'tls-crypt /etc/openvpn/server/tc.key',

                # Network topology
                'topology subnet',

                # Log
                f'log {cfg["openvpn_log_file"]}',

                # Configure server mode and supply a VPN subnet
                # for OpenVPN to draw client addresses from.
                f'server {ip.ip} {ip.netmask}',

                # Limit server to a maximum of concurrent clients.
                f'max-clients {params.get("connections")}',

                f'keepalive {params.get("keepalive", "10 20")}',

                # Select a cryptographic cipher.
                'data-ciphers AES-256-CBC',
                'cipher AES-256-CBC',

                # The persist options will try to avoid accessing certain resources on restart
                # that may no longer be accessible because of the privilege downgrade.
                'persist-key',
                'persist-tun',

                # Output a short status file showing current connections, truncated
                # and rewritten every minute.
                f'status {cfg["openvpn_status_file"]} 10',

                # Set the appropriate level of log file verbosity.
                'verb 3',

                # Require the client to provide a username/password for authentication.
                # OpenVPN will run this script to validate the username/password provided by the client.
                'auth-user-pass-verify /etc/openvpn/server/auth-script.py via-file',

                # Specify a directory dir for temporary files
                'tmp-dir /dev/shm',

                'script-security 2',

                # The client is required to supply a valid certificate
                'verify-client-cert require',

                # Use the authenticated username as the common name
                'username-as-common-name',

                # After successful user/password authentication, the OpenVPN server will generate tmp token valid for 12 hours
                # On the following renegotiations, the OpenVPN client will pass this token instead of the users password
                f'auth-gen-token {params.get("vpnTmpTokenTime", "43200")}',

                # Allow multiple clients with the same common name to concurrently connect
                # 'duplicate-cn',

                # OpenVPN will internally route client-to-client traffic rather than pushing all client-originating traffic to the TUN/TAP interface.
                'client-to-client',

                'explicit-exit-notify',

                # call these scripts once OpenVPN starts and stops
                'up /etc/openvpn/server/up-script.py',
                'down /etc/openvpn/server/down-script.py',

                # set the allowed servers as env variable for the scripts
                f'setenv AUTH_SCRIPT_ALLOWED_SERVERS {",".join(vpn_portal_urls)}'
            ]

            # Split tunnel
            if params['routeAllTrafficOverVpn'] is True:
                # this directive will configure all clients to redirect their default
                # network gateway through the VPN
                commands.append('push "redirect-gateway def1 bypass-dhcp"')
            else:
                # we are using client-connect script only if we need to send ospf routes to the client dynamically
                commands.append('client-connect /etc/openvpn/server/client-connect.py')

            # DNS options
            dns_ips = params.get('dnsIps', [])
            for ip in dns_ips:
                commands.append(f'push "dhcp-option DNS {ip}"')

            if dns_ips and params.get('dnsBlockOutside'):
                commands.append('push "block-outside-dns"')

            for name in params.get('dnsDomains', []):
                commands.append(f'push "dhcp-option DOMAIN {name}"')

            # write the config file from Python (and not by 'echo' shell commands)
            for command in commands:
                if fw_input_validation.has_control_chars(command):
                    raise Exception(f'invalid server.conf line {command!r}')
            fw_os_utils.write_private_file(cfg["openvpn_server_conf_file"], '\n'.join(commands) + '\n', mode=0o644)

            self.log.info('the server.conf file configured successfully')
        except Exception as e:
            self.log.error(f'_configure_server_file({str(params)}): failed to configure remoteVPN server.conf. err={str(e)}')
            raise e

    def on_router_is_started(self):
        # This hook should start the VPN server immediately after the VPP is begun.
        # If the VPN is already running for some reason,
        # we restart it to make sure our unique settings to mirror traffic into the VPP are applied.
        return self.start(restart=True)

    def on_router_is_stopped(self):
        return self.stop()

    def on_router_is_stopping(self):
        return self.stop()

    def start(self, restart=False):
        # don't start if vpp is down
        router_is_running = fw_os_utils.vpp_does_run()
        if not router_is_running:
            return

        if self.is_app_running():
            if not restart:
                return
            self.log.info(f'start({restart}): restarting daemon')
            self.stop()

        self.log.info(f'daemon is being started')

        self._create_symbol_links(skip_if_exist=True)
        os.system(f'sudo openvpn --config {cfg["openvpn_server_conf_file"]} --daemon')

    def stop(self):
        if self.is_app_running():
            killed = fw_os_utils.kill_process('openvpn')
            if killed:
                self.log.info(f'daemon is stopped')
                os.system(f'echo "" > {cfg["openvpn_status_file"]}')
            else:
                self.log.excep('stop(): failed to kill openvpn')

    def on_watchdog(self):
        vpn_runs = self.is_app_running()
        router_is_running = fw_os_utils.vpp_does_run()
        if not vpn_runs and router_is_running:
            self.start()

    def is_app_running(self):
        return True if self._openvpn_pid() else False

    def get_log_filename(self):
        return cfg['openvpn_log_file']

    def get_interfaces(self, type='lan', vpp_interfaces=False, linux_interfaces=False):
        if type == 'wan':
            return []

        if not self.is_app_running():
            return []

        if not fw_os_utils.vpp_does_run():
            return []

        res = []
        if vpp_interfaces:
            with open(cfg['app_database_file'], 'r') as json_file:
                data = json.load(json_file)
                tun_vpp_if_name = data.get('tun_vpp_if_name')
                if tun_vpp_if_name:
                    res.append(tun_vpp_if_name)

        if linux_interfaces:
            res.append(cfg['openvpn_interface_name'])

        return res

    def get_statistics(self):
        response = {
            'clients': {}
        }

        if not exists(cfg["openvpn_status_file"]):
            return response

        try:
            with open(cfg["openvpn_status_file"], 'r') as logfile:
                status_lines = logfile.read().splitlines()

                # sometimes the log file contains one line with empty string
                if not status_lines or (len(status_lines) == 1 and status_lines[0] == ''):
                    return response

                routing_table_idx = status_lines.index("ROUTING TABLE")
                global_stats_idx = status_lines.index("GLOBAL STATS")

                client_list = status_lines[:routing_table_idx]
                for line in client_list[3:]:
                    # line = 'test@flexiwan.com ,192.168.1.1:57662,22206,13194,2021-12-22 11:57:33'
                    fields = line.split(',')
                    username = fields[0]
                    real_addr = fields[1]
                    key = username + real_addr
                    response['clients'][key] = { # support multiple clients with same username
                        'Common Name': username,
                        'Real Address': real_addr,
                        'Bytes Received':  fields[2],
                        'Bytes Sent': fields[3],
                        'Connected Since': fields[4],
                    }

                routing_table = status_lines[routing_table_idx:global_stats_idx]
                for line in routing_table[2:]:
                    # line = '50.50.50.2,shneorp@flexiwan.com ,192.168.1.1:1052,2021-12-22 11:57:33'
                    fields = line.split(',')
                    username = fields[1]
                    real_addr = fields[2]
                    key = username + real_addr
                    if key in response['clients']:
                        response['clients'][key]['Virtual Address'] = fields[0]

            return response
        except Exception as e:
            self.log.error(f"get_statistics(): {str(e)}")
            return response

    def get_fwdump_files(self):
        return [
            cfg["openvpn_status_file"],
            cfg["openvpn_server_conf_file"],
            cfg["openvpn_scripts_log_file"],
            cfg["openvpn_log_file"],
        ]

    def get_networks(self, for_bgp=False, for_ospf=False):
        networks = []
        with open(cfg['app_database_file'], 'r') as json_file:
            data = json.load(json_file)
            tun_vpp_if_addr = data.get('tun_vpp_if_addr')
            if tun_vpp_if_addr:
                networks.append(tun_vpp_if_addr)
        return networks
