#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2025  flexiWAN Ltd.
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
import sys
import json
from os.path import exists
import requests
from requests.models import PreparedRequest
import urllib.request
import tempfile
import shutil
import re
import subprocess
import time
import concurrent.futures

current_dir = os.path.dirname(os.path.realpath(__file__))
applications_dir = os.path.join(current_dir, "../")
agent_dir = os.path.join(applications_dir, "../")
sys.path.append(current_dir)
sys.path.append(applications_dir)
sys.path.append(agent_dir)

from applications.fwapplication_interface import FwApplicationInterface
import fw_os_utils
import fw_input_validation
from build.config import config

COUNT_TO_APPLY_WATCHDOG = 10

class Application(FwApplicationInterface):

    def __init__(self):
        super(Application, self).__init__()
        self.server = 'http://localhost:'
        self.db_file = '/etc/ntopng/ntopng_db.json'
        self.ntop_conf = '/etc/ntopng/ntopng.conf'
        self.api_to_url = {
            'get_active_interfaces': '/lua/rest/v2/get/ntopng/interfaces.lua',
            'get_active_flows': '/lua/rest/v2/get/flow/active.lua',
            'get_active_hosts': '/lua/rest/v2/get/host/active.lua',
            'get_top_applications': '/lua/rest/v2/get/interface/l7/stats.lua',
            'get_host_applications': '/lua/rest/v2/get/host/l7/stats.lua', # ?ifid=14&host=192.168.21.1&breed=false&ndpi_category=false&collapse_stats=false
        }
        data = self._read_db_data()
        self.serverPort = data.get('serverPort', '9000')
        self.affinity = data.get('affinity', 0)
        self.app_running = self.is_app_running()
        self.watchdog_counter = 0

    def install(self, params):
        """Install NTOP-NG on host.

        :param params - ntop ng parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            installed = os.popen("dpkg -l | grep -E '^ii' | grep -E 'ii\s+ntopng\s'").read()
            dir_is_empty = not exists('/etc/ntopng') or len(os.listdir('/etc/ntopng')) == 0
            if installed and not dir_is_empty:
                self.log.info(f'NTOP-NG already installed, skipping')
                return

            # Install ntop repository
            self.log.info("Install NTOP-NG repository")
            distro = os.popen('lsb_release -rs').read().strip()
            base_url = 'https://packages.ntop.org/apt-stable'
            key_url = f'{base_url}/ntop.key'
            repo_url = f'{base_url}/{distro}'

            commands = [
                f'apt-key adv --fetch-keys {key_url}',
                'apt-get update && apt-get install -y software-properties-common',
                'add-apt-repository universe',
                f'echo deb {repo_url}/ x64/ > /etc/apt/sources.list.d/ntop.list',
                f'echo deb {repo_url}/ all/ >> /etc/apt/sources.list.d/ntop.list'
            ]
            fw_os_utils.run_linux_commands(commands)

            # Installing ntop packages
            self.log.info("Install NTOP-NG packages")
            commands = [
                'apt-get clean all',
                'apt-get update',
                'apt-get install -y pfring-dkms nprobe ntopng n2disk cento',
            ]
            fw_os_utils.run_linux_commands(commands)

            self.log.info(f'NTOP-NG application installed successfully')

        except Exception as e:
            self.log.error(f"install(): {str(e)}")
            # call uninstall function to revert the installation
            self.uninstall()
            raise e

    def _read_db_data(self):
        if not exists(self.db_file):
            return {}
        with open(self.db_file, 'r') as json_file:
            data = json.load(json_file)
        return data

    def _write_db_data(self, data):
        with open(self.db_file, 'w') as json_file:
            json.dump(data, json_file)

    def _get_tap_name_from_if_name(self, if_name):
        # Interfaces can have up to 15 characters, but we append 9 additional characters.
        # To ensure uniqueness and stay within length limits, we retain only the last 6 characters.
        if len(if_name) > 6:
            if_name = if_name[-6:]
        return f'tap_{if_name}.ntop'


    def _provision_ntop_conf_file(self, params):
        prev_file = self.ntop_conf + "~"
        new_file = self.ntop_conf
        shutil.copy(new_file, prev_file)
        with open(prev_file, 'r') as orig_file:
            lines = orig_file.readlines()

        new_lines = []
        for line in lines:
            # Check tags to remove -i, -w, -l
            if not re.match(r'^\s*-i=|^\s*-w=|^\s*-l=', line):
                new_lines.append(line)

        # At the end of the file include the relevant config
        # Interfaces
        for interface in params['interfaces']:
            if type(interface)==dict:
                # PPPoE is a TUN interface, and spanning between TAP and TUN is not supported in VPP.
                # Additionally, the DPDK TUN interface used by PPPoE lacks proper span functionality.
                # As a workaround, for PPPoE interfaces, use the Linux interface name directly
                # without TAP and span configuration.
                #
                if interface['ifType'] == 'pppoe':
                    new_lines.append(f'-i={config.pppoe.if_name_prefix}-{interface["ifName"]}\n')
                    continue

                tap_name = self._get_tap_name_from_if_name(interface['ifName'])
                new_lines.append(f'-i={tap_name}\n')
            elif type(interface)==str:
                new_lines.append(f'-i={interface}\n')
            else:
                self.log.error(f"_provision_ntop_conf_file: unknown interface type {interface}")
        # Port
        new_lines.append(f'-w={params.get("serverPort", "9000")}\n')
        # Login
        new_lines.append('-l=0\n')

        with open(new_file, 'w') as new_file:
            new_file.writelines(new_lines)

    def _validate_params(self, params):
        """Validate parameters that are used in 'fwagent' command lines
        and in the ntopng.conf file.
        """
        for interface in params.get('interfaces', []):
            if type(interface)==dict:
                fw_input_validation.ensure_ifname(interface.get('ifName'), 'ifName')
                dev_id = interface.get('devId')
                if interface.get('ifType') != 'pppoe' and \
                   (not fw_input_validation.is_shell_safe_word(dev_id) or dev_id.startswith('-')):
                    raise Exception(f'invalid devId {dev_id!r}')
            elif type(interface)==str:
                fw_input_validation.ensure_ifname(interface, 'interface')
        fw_input_validation.ensure_int(params.get('serverPort', '9000'), 'serverPort', 1, 65535)

    def configure(self, params):
        """Configure NTOPNG server on host.

        :param params: params - ntopng parameters

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            self.log.info(f"NTOP-NG application configurations")

            self._validate_params(params)

            # Create databases of interfaces
            data = self._read_db_data()
            data['interfaces'] = params.get('interfaces', [])
            data['serverPort'] = params.get('serverPort', '9000')
            data['affinity'] = params.get('affinity', 0)
            self.serverPort = data['serverPort']
            self.affinity = data['affinity']
            self._write_db_data(data)

            password = params.get('adminPassword', None)
            if password: self.set_password(password)

            # Modify ntopng.conf to listen to interfaces
            self._provision_ntop_conf_file(params)

            self.start(restart=True)

        except Exception as e:
            self.log.error(f"configure({params}): {str(e)}")
            raise e

    def uninstall(self, files_only=False):
        """Remove NTOPNG from host.

        :returns: (True, None) tuple on success, (False, <error string>) on failure.
        """
        try:
            self.stop()

            self.log.info("Uninstalling NTOP-NG packages")
            commands = []
            if not files_only:
                commands.append('sudo apt remove -y pfring-dkms nprobe ntopng n2disk cento')
                commands.append('sudo apt remove -y ntopng-data')
                commands.append('sudo apt remove -y apt-ntop-stable')
                commands.append('sudo rm -f /etc/apt/sources.list.d/ntop.list')
                commands.append('sudo apt remove -y ntop-license')
                commands.append('sudo dpkg -P ntopng')

            # Remove ntopng folder when removing only files, this is called when removing router package
            commands.append('sudo rm -rf /etc/ntopng/')

            fw_os_utils.run_linux_commands(commands)

        except Exception as e:
            self.log.error(f"uninstall(): {str(e)}")
            raise e

    def on_router_is_started(self):
        # This hook should start the NTOPNG immediately after the VPP started.
        # If the NTOPN is already running for some reason,
        # we restart it to make sure settings are applied correctly
        return self.start(restart=True)

    def on_router_is_stopped(self):
        return self.stop()

    def on_router_is_stopping(self):
        return self.stop()

    def _configure_tap_in_vpp(self, interface):
        try:
            host_name = self._get_tap_name_from_if_name(interface)
            dev_id = f'app_com.flexiwan.monitorntop_{interface}'
            addr = 'NONE'
            fwagent_cmd = f'configure router interfaces create --type lan --host_if_name {host_name} --addr {addr} --no_vppsb --no_ospf --no_bgp --no_features --tap --dev_id {dev_id}'
            response_data = fw_os_utils.run_fwagent_command(fwagent_cmd, self.identifier)
            vpp_name = response_data.get('tun_vpp_if_name')
            if not vpp_name:
                raise Exception(f'monitorntop: create_tap_in_vpp({addr}): The name of the interface created in VPP was not returned as expected. response_data={str(response_data)}')

            self.log.info(f'TAP created in vpp. vpp_if_name={vpp_name}')
            return vpp_name

        except subprocess.CalledProcessError as exc:
            self.log.error(f'monitorntop: create_tap_in_vpp({addr}): {str(exc.output)}')
            raise exc
        except Exception as e:
            self.log.error(f'monitorntop: create_tap_in_vpp({addr}): {str(e)}')
            raise e

    def _remove_tap_from_vpp(self, interface):
        try:
            addr = 'NONE'
            fwagent_cmd = f'configure router interfaces delete --ignore_errors --type lan --vpp_if_name {interface} --addr {addr} --no_ospf --no_bgp --no_features'
            fw_os_utils.run_fwagent_command(fwagent_cmd, self.identifier)
            self.log.info(f'TAP removed from vpp. vpp_if_name={interface}')

        except subprocess.CalledProcessError as exc:
            self.log.error(f'monitorntop: remove_tap_from_vpp({addr}): {str(exc.output)}')
            raise exc
        except Exception as e:
            self.log.error(f'monitorntop: remove_tap_from_vpp({addr}): {str(e)}')
            raise e

    def _configure_span_in_vpp(self, src_dev_id, dst_tap):
        try:
            fwagent_cmd = f'configure router span create --src_dev_id {src_dev_id} --dest_vpp_if_name {dst_tap}'
            fw_os_utils.run_fwagent_command(fwagent_cmd, self.identifier)
            self.log.info(f'Span created in vpp. src_dev_id={src_dev_id}')

        except subprocess.CalledProcessError as exc:
            self.log.error(f'monitorntop: create_span_in_vpp({src_dev_id}, {dst_tap}): failed with {exc.returncode}: {str(exc.output)}')
            raise exc
        except Exception as e:
            self.log.error(f'monitorntop: create_tun_in_vpp({src_dev_id}, {dst_tap}): {str(e)}')
            raise e

    def _remove_span_from_vpp(self, src_dev_id):
        try:
            fwagent_cmd = f'configure router span delete --src_dev_id {src_dev_id} --ignore_errors'
            fw_os_utils.run_fwagent_command(fwagent_cmd, self.identifier)
            self.log.info(f'Span removed from vpp. src_dev_id={src_dev_id}')

        except subprocess.CalledProcessError as exc:
            self.log.error(f'monitorntop: remove_span_from_vpp({src_dev_id}): failed with {exc.returncode}: {str(exc.output)}')
            raise exc
        except Exception as e:
            self.log.error(f'monitorntop: remove_tun_from_vpp({src_dev_id}): {str(e)}')
            raise e

    def start(self, restart=False):
        # don't start if vpp is down
        router_is_running = fw_os_utils.vpp_does_run()
        if not router_is_running:
            return

        if restart:
            self.log.info(f'start({restart}): restarting NTOP-NG')
            self.stop()

        # Add tap interfaces to vpp
        data = self._read_db_data()
        interfaces = data.get('interfaces', [])
        data['taps'] = []

        for interface in interfaces:
            # PPPoE should not have a tap interface. See explanation in _configure_tap_in_vpp
            if interface['ifType'] == 'pppoe':
                continue

            vpp_tap_name = self._configure_tap_in_vpp(interface['ifName'])
            self._configure_span_in_vpp(interface['devId'], vpp_tap_name)
            data['taps'].append({'devId':interface['devId'], 'vpp_tap_name':vpp_tap_name})

        self._write_db_data(data)

        # Sleep a bit before restarting the service to make sure everything configured
        time.sleep(5)
        os.system(f'sudo systemctl restart ntopng')
        self.log.info(f'NTOP-NG is being started')
        self.watchdog_counter = 0
        self.app_running = True
        self.set_affinity(self.affinity)

    def stop(self):
        self.log.info(f'Stopping NTOPNG')
        if self.is_app_running():
            os.system(f'sudo systemctl stop ntopng')
            self.watchdog_counter = 0
            self.app_running = False

        if fw_os_utils.vpp_does_run() and self.is_daemon_running():
            # Remove tap interfaces from vpp
            data = self._read_db_data()
            interfaces = data.get('taps', [])

            for interface in interfaces:
                self._remove_span_from_vpp(interface['devId'])
                self._remove_tap_from_vpp(interface['vpp_tap_name'])

        self.log.info(f'NTOP-NG is stopped')

    def set_affinity(self, affinity_in):
        # Convert affinity to number
        try:
            affinity = int(affinity_in)
        except ValueError:
            affinity = 0
        # If affinity larger than number of CPUs, use 0 - could be if HW modified
        if affinity >= os.cpu_count():
            affinity = 0
        SET_AFFINITY_TRIALS = 30
        for t in range(SET_AFFINITY_TRIALS):
            ntop_pid = fw_os_utils.pid_of('ntopng-main')
            if ntop_pid: break
            time.sleep(1)
        if ntop_pid:
            os.sched_setaffinity(int(ntop_pid), {affinity})
        self.log.debug(f'Setting affinity for NTOP-NG: pid={ntop_pid}, affinity={affinity}')

    def on_watchdog(self):
        # Sometimes after start, service is not running and it causes configuration loop (start /stop)
        # Need to give enough time after start until we start watchdog checking
        self.watchdog_counter += 1
        if self.watchdog_counter < COUNT_TO_APPLY_WATCHDOG: return
        app_is_running = self.is_app_running()
        self.app_running = app_is_running
        router_is_running = fw_os_utils.vpp_does_run()
        if not app_is_running and router_is_running:
            self.log.debug("Starting NTOP-NG on watchdog")
            self.start()

    def is_app_running(self):
        try:
            status = subprocess.check_output(['systemctl', 'is-active', 'ntopng']).decode().strip()
            return True if status=='active' else False
        except:
            return False

    def is_daemon_running(self):
        try:
            status = subprocess.check_output(['fwagent', 'show', '--status', 'daemon']).decode().strip()
            return True if status=='running' else False
        except:
            return False

    def get_log_filename(self):
        return '/var/log/ntopng.log'

    def get_interfaces(self, type='lan', vpp_interfaces=False, linux_interfaces=False):
         return []

    def get_statistics(self):
        response = {}
        if self.app_running:
            res, err = self.exec_server_request(
                url='/lua/rest/v2/get/system/status.lua',
                query={},
                method='GET',
                headers={},
                body=None
            )
            ifres, iferr = self.exec_server_request(
                url='/lua/rest/v2/get/system/health/interfaces.lua',
                query={},
                method='GET',
                headers={},
                body=None
            )
            if (not err) and (not iferr):
                response = {
                    'version': res['license_info']['version'],
                    'ntopng_ram': res['resources_used']['ntopng']['ram']['bytes_used'],
                    'interfaces': ifres['interfaces_stats']
                }
        return response

    def set_password(self, password):
        self.log.info("Setting NTOP-NG password")
        # To configure password, setup the conf only loopback interface
        # Assuming that after setting the password, the conf will be initialized properly
        # In the configure function
        self._provision_ntop_conf_file({
            'serverPort':self.serverPort,
            'interfaces': ['lo']  # Set loopback interface when setting the password
        })
        os.system(f'sudo systemctl restart ntopng')
        # Try to execute an API with a timeout of 30 sec
        SET_PASSWORD_TRIALS = 30
        set_password_success = False
        for t in range(SET_PASSWORD_TRIALS):
            res, err = self.exec_server_request(
                url='/lua/rest/v2/edit/ntopng/user.lua',
                query={},
                method='POST',
                headers={'accept': 'application/json', 'Content-Type': 'application/json'},
                body = {
                    'username': 'admin',
                    'password': password,
                    'confirm_password': password
                }
            )
            if not err:
                # Success, break
                set_password_success = True
                break
            # sleep 1 sec and try again
            time.sleep(1)
        os.system(f'sudo systemctl stop ntopng')
        if not set_password_success: # Not able to set password
            self.log.error(f"Unable to set password for NTOP-NG after {t} trials")
            raise Exception("Unable to set password for NTOP-NG")

    def get_fwdump_files(self):
        return [
            '/var/log/ntopng.log',
            '/etc/ntopng/ntopng.conf',
            '/etc/ntopng/ntopng_db.json'
        ]

    def get_networks(self, for_bgp=False, for_ospf=False):
        networks = []
        return networks

    def exec_server_request(self, query, url, method, headers={}, body=None):
        try:
            req = PreparedRequest()
            url = self.server + self.serverPort + url
            req.prepare_url(url, query)
            if (method=='GET'):      resp = requests.get(req.url, headers=headers)
            elif (method=='POST'):   resp = requests.post(req.url, json=body, headers=headers)
            elif (method=='PUT'):    resp = requests.put(req.url, json=body, headers=headers)
            elif (method=='DELETE'): resp = requests.delete(req.url,json=body, headers=headers)
            else: raise Exception ('Invalid method')

            if resp.status_code != 200 and not '"rc_str":"OK"' in resp.text: raise Exception ('Bad response')
            if resp.headers['Content-Type'] != 'application/json': raise Exception('Wrong response type')

            # Some responses (such as in password change) has some text before the real response
            parsed = json.loads(resp.text.splitlines()[-1])
            return (parsed['rsp'], None)
        except Exception as e:
            # self.log.error(f"Error executing NTOPNG request {str(e)}")
            return ({}, "Exec Request Error")

    def exec_application_action(self, **params):
        '''
        {
            "params": {
                "identifier": "com.flexiwan.monitorntop",
                "applicationApi": "get_active_flows",
                "applicationQueries": { ... }
                "applicationParams": { ... }
            }
        }
        '''
        self.log.info(f'exec_application_action called with {params}')
        url = self.api_to_url.get(params['applicationApi'])
        if not url: return {'ok':0, 'message':'API not found'}
        res, err = self.exec_server_request(
            url=url,
            query=params.get('applicationQueries',{}),
            method='GET',
            headers={},
            body=None
        )
        if not err:
            return {'identity':'com.flexiwan.monitorntop',
                    'ok':1, 'message':res}
        else:
            return {'identity':'com.flexiwan.monitorntop',
                    'ok':0, 'message':{'errors' : err}}
