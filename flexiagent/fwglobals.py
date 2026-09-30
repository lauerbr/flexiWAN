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
import json
import os
import Pyro4
import random
import re
import signal
import string
import traceback
import yaml
from fwqos import FwQoS
import fwutils
import threading
import fw_os_utils
import fw_redact
import fw_vpp_coredump_utils
import fwlte
import ipaddress

from pathlib import Path

from fwsqlitedict import FwSqliteDict

from fwagent import FwAgent
from fwmessage_handler import FwMessageHandler
from fwdhcp_server import FwDhcpServer
from fw_fqdn_resolver import FwFqdnResolver
from fwobject import FwObject
from fwrouter_api import FWROUTER_API
from fwsystem_api import FWSYSTEM_API
from fwagent_api import FWAGENT_API
from fwapplications_api import FWAPPLICATIONS_API
from os_api import OS_API
from fwlog import FwObjectLogger, FwLogFile, FwLogSyslog, FwLogDevNull
from fwlog import FWLOG_LEVEL_INFO, FWLOG_LEVEL_DEBUG
from fwpolicies import FwPolicies
from fwrouter_cfg import FwRouterCfg
from fwroutes import FwRoutes
from fwstats import FwStatistics
from fwsystem_cfg import FwSystemCfg
from fwjobs import FwJobs
from fwstun import FwStun
from fwpppoe import FwPppoeClient
from fwthread import FwRouterThreading
from fwwan_monitor import FwWanMonitor
from fwwatchdog import FwWatchdog
from fwwatchdog import FwRlock
from fwikev2 import FwIKEv2
from fw_traffic_identification import FwTrafficIdentifications
from fwnotifications import FwNotifications
from fw_nat_manager import FwNatSessionsManager
from build.config import config

# sync flag indicated if module implement sync logic.
# IMPORTANT! Please keep the list order. It indicates the sync priorities
modules = {
    'fwsystem_api':       { 'module': __import__('fwsystem_api'),       'sync': True,  'object': 'system_api' },       # fwglobals.g.system_api
    'fwagent_api':        { 'module': __import__('fwagent_api'),        'sync': False, 'object': 'agent_api' },        # fwglobals.g.agent_api
    'fwrouter_api':       { 'module': __import__('fwrouter_api'),       'sync': True,  'object': 'router_api' },       # fwglobals.g.router_api
    'os_api':             { 'module': __import__('os_api'),             'sync': False, 'object': 'os_api' },           # fwglobals.g.os_api
    'fwapplications_api': { 'module': __import__('fwapplications_api'), 'sync': True,  'object': 'applications_api' }, # fwglobals.g.applications_api,
}

cli_commands = {
    'configure':    {'help': 'Configure flexiEdge components', 'modules': []},
}
cli_modules = {
    # Will be filled automatically out of content of the 'cli' folder
}

request_handlers = {

    ##############################################################
    # DEVICE API-s
    # ------------------------------------------------------------
    # These API-s implement interface between FlexiEdge device
    # and FlexiManage server. The device API-s are invoked using
    # requests sent by server to device over secured connection.
    ##############################################################

    # Agent API
    'get-device-info':                   {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-device-stats':                  {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-device-logs':                   {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-device-packet-traces':          {'name': '_call_agent_api'},
    'get-device-os-routes':              {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-device-config':                 {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'upgrade-device-sw':                 {'name': '_call_agent_api'},
    'upgrade-linux-sw':                  {'name': '_call_agent_api'},
    'reset-device':                      {'name': '_call_agent_api'},
    'sync-device':                       {'name': '_call_agent_api'},
    'get-wifi-info':                     {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-lte-info':                      {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'reset-lte':                         {'name': '_call_agent_api'},
    'modify-lte-pin':                    {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'activate-sim-slot':                 {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-device-certificate':            {'name': '_call_agent_api'},
    'get-bgp-status':                    {'name': '_call_agent_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get-router-stats':                  {'name': '_call_agent_api'},
    'get-dhcp-status':                   {'name': '_call_agent_api'},

    # Aggregated API
    'aggregated':                   {'name': '_call_aggregated', 'sign': True},

    # Router API
    'start-router':                 {'name': '_call_router_api', 'sign': True},
    'stop-router':                  {'name': '_call_router_api', 'sign': True},
    'add-interface':                {'name': '_call_router_api', 'sign': True},
    'remove-interface':             {'name': '_call_router_api', 'sign': True},
    'modify-interface':             {'name': '_call_router_api', 'sign': True},
    'add-route':                    {'name': '_call_router_api', 'sign': True},
    'remove-route':                 {'name': '_call_router_api', 'sign': True},
    'add-tunnel':                   {'name': '_call_router_api', 'sign': True},
    'remove-tunnel':                {'name': '_call_router_api', 'sign': True},
    'modify-tunnel':                {'name': '_call_router_api', 'sign': True},
    'add-dhcp-config':              {'name': '_call_router_api', 'sign': True},
    'remove-dhcp-config':           {'name': '_call_router_api', 'sign': True},
    'add-application':              {'name': '_call_router_api', 'sign': True},
    'remove-application':           {'name': '_call_router_api', 'sign': True},
    'add-multilink-policy':         {'name': '_call_router_api', 'sign': True},
    'remove-multilink-policy':      {'name': '_call_router_api', 'sign': True},
    'add-ospf':                     {'name': '_call_router_api', 'sign': True},
    'remove-ospf':                  {'name': '_call_router_api', 'sign': True},
    'add-routing-bgp':              {'name': '_call_router_api', 'sign': True},
    'remove-routing-bgp':           {'name': '_call_router_api', 'sign': True},
    'modify-routing-bgp':           {'name': '_call_router_api', 'sign': True},
    'add-routing-filter':           {'name': '_call_router_api', 'sign': True},
    'remove-routing-filter':        {'name': '_call_router_api', 'sign': True},
    'add-switch':                   {'name': '_call_router_api', 'sign': True},
    'remove-switch':                {'name': '_call_router_api', 'sign': True},
    'add-firewall-policy':          {'name': '_call_router_api', 'sign': True},
    'remove-firewall-policy':       {'name': '_call_router_api', 'sign': True},
    'add-qos-traffic-map':          {'name': '_call_router_api', 'sign': True},
    'remove-qos-traffic-map':       {'name': '_call_router_api', 'sign': True},
    'add-qos-policy':               {'name': '_call_router_api', 'sign': True},
    'remove-qos-policy':            {'name': '_call_router_api', 'sign': True},
    'add-vxlan-config':             {'name': '_call_router_api', 'sign': True},
    'remove-vxlan-config':          {'name': '_call_router_api', 'sign': True},
    'modify-vxlan-config':          {'name': '_call_router_api', 'sign': True},
    'add-vrrp-group':               {'name': '_call_router_api', 'sign': True},
    'remove-vrrp-group':            {'name': '_call_router_api', 'sign': True},
    'add-lan-nat-policy':           {'name': '_call_router_api', 'sign': True},
    'remove-lan-nat-policy':        {'name': '_call_router_api', 'sign': True},
    'add-routing-general':          {'name': '_call_router_api', 'sign': True},
    'remove-routing-general':       {'name': '_call_router_api', 'sign': True},

    # System API
    'add-lte':                      {'name': '_call_system_api', 'sign': True},
    'remove-lte':                   {'name': '_call_system_api', 'sign': True},
    'add-notifications-config':     {'name': '_call_system_api', 'sign': True},
    'remove-notifications-config':  {'name': '_call_system_api', 'sign': True},
    'add-link-monitor':             {'name': '_call_system_api', 'sign': True},
    'modify-link-monitor':          {'name': '_call_system_api', 'sign': True},
    'remove-link-monitor':          {'name': '_call_system_api', 'sign': True},
    'set-cpu-info':                 {'name': '_call_system_api', 'sign': True},

    # Applications api
    'add-app-install':             {'name': '_call_applications_api', 'sign': True},
    'remove-app-install':          {'name': '_call_applications_api', 'sign': True},
    'add-app-config':              {'name': '_call_applications_api', 'sign': True},
    'remove-app-config':           {'name': '_call_applications_api', 'sign': True},
    'exec-app-action':             {'name': '_call_applications_api', 'processing': {'synchronous': True, 'exclusive': False}},

    # OS API
    'exec_timeout':                {'name': '_call_os_api', 'processing': {'synchronous': True, 'exclusive': False}},
    'get_file':                    {'name': '_call_os_api', 'processing': {'synchronous': True, 'exclusive': False}},

    # CLI
    'cli-command':                 {'name': '_call_cli_command', 'sign': False},
}

g             = None
g_initialized = 0
log           = None

@Pyro4.expose
class Fwglobals(FwObject):
    """This is global data class representation.

    """
    class FwConfiguration:
        """This is configuration class representation.

        :param filename:    YAML configuration file name.
        :param data_path:   Path to token file.
        """
        def __init__(self, filename, data_path, log=None):
            """Constructor method
            """
            DEFAULT_BYPASS_CERT    = False
            DEFAULT_DEBUG          = False
            DEFAULT_MANAGEMENT_URL = 'https://manage.flexiwan.com:443'
            DEFAULT_TOKEN_FILE     = data_path + 'token.txt'
            DEFAULT_UUID           = None
            DEFAULT_WAN_MONITOR_UNASSIGNED_INTERFACES = True
            DEFAULT_WAN_MONITOR_SERVERS = ['1.1.1.1','8.8.8.8']
            DEFAULT_WAN_MONITOR_PROBE_TIMEOUT = 1000  # msec
            DEFAULT_WAN_MONITOR_WINDOW_SIZE = 20
            DEFAULT_WAN_MONITOR_THRESHOLD = 12
            DEFAULT_DAEMON_SOCKET_NAME  = f"/run/{config.company}/fwagent.sock"  # Unix socket used for RPC to daemon
            DEFAULT_WATCHDOG_DEADLOCK_ENABLED     = True
            DEFAULT_WATCHDOG_CONNECTION_ENABLED   = True
            DEFAULT_WATCHDOG_ROUTER_CFG_WINDOW    = 240  # If user changed configuration in last 240 seconds, VPP might be stopped
            DEFAULT_LTE_SWITCHOVER_INTERVAL           = 60 * 10 #  10 minutes
            DEFAULT_LTE_SWITCHOVER_OPERATOR_INTERVAL  = 60 * 2 #  2 minutes
            DEFAULT_MESSAGE_TRANSMISSION_DELAY_BETWEEN_CHUNKS  = 10 # in milliseconds
            DEFAULT_VROUTER_API_READ_TIMEOUT = 30 # in seconds
            DEFAULT_FQDN_RESOLUTION_INTERVAL = 300 # in seconds, 5 min
            try:
                with open(filename, 'r') as conf_file:
                    conf = yaml.load(conf_file, Loader=yaml.SafeLoader)
                agent_conf = conf.get('agent', {})
                self.BYPASS_CERT    = agent_conf.get('bypass_certificate', DEFAULT_BYPASS_CERT)
                self.DEBUG          = agent_conf.get('debug',  DEFAULT_DEBUG)
                self.MANAGEMENT_URL = agent_conf.get('server', DEFAULT_MANAGEMENT_URL)
                self.TOKEN_FILE     = agent_conf.get('token',  DEFAULT_TOKEN_FILE)
                self.UUID           = agent_conf.get('uuid',   DEFAULT_UUID)

                # WAN Monitoring
                self.WAN_MONITOR_UNASSIGNED_INTERFACES = agent_conf.get('monitor_wan',{}).get('monitor_unassigned_interfaces', DEFAULT_WAN_MONITOR_UNASSIGNED_INTERFACES)
                self.WAN_MONITOR_SERVERS               = agent_conf.get('monitor_wan',{}).get('servers', DEFAULT_WAN_MONITOR_SERVERS)
                self.WAN_MONITOR_PROBE_TIMEOUT         = agent_conf.get('monitor_wan',{}).get('probe_timeout', DEFAULT_WAN_MONITOR_PROBE_TIMEOUT)
                self.WAN_MONITORING_WINDOW_SIZE        = DEFAULT_WAN_MONITOR_WINDOW_SIZE
                self.WAN_MONITORING_THRESHOLD          = DEFAULT_WAN_MONITOR_THRESHOLD

                # FQDN Resolver
                self.FQDN_RESOLUTION_INTERVAL          = agent_conf.get('fqdn_resolver',{}).get('resolution_interval', DEFAULT_FQDN_RESOLUTION_INTERVAL)

                # LTE Switchover
                self.LTE_SWITCHOVER_INTERVAL           = DEFAULT_LTE_SWITCHOVER_INTERVAL
                self.LTE_SWITCHOVER_OPERATOR_INTERVAL  = DEFAULT_LTE_SWITCHOVER_OPERATOR_INTERVAL

                self.DAEMON_SOCKET_NAME                = agent_conf.get('daemon_socket',  DEFAULT_DAEMON_SOCKET_NAME)
                self.WATCHDOG_DEADLOCK_ENABLED         = agent_conf.get('watchdog',{}).get('deadlock',{}).get('enabled',  DEFAULT_WATCHDOG_DEADLOCK_ENABLED)
                self.WATCHDOG_CONNECTION_ENABLED       = agent_conf.get('watchdog',{}).get('connection',{}).get('enabled',  DEFAULT_WATCHDOG_CONNECTION_ENABLED)
                self.WATCHDOG_ROUTER_CFG_WINDOW        = agent_conf.get('watchdog',{}).get('connection',{}).get('router_cfg_window',  DEFAULT_WATCHDOG_ROUTER_CFG_WINDOW)

                # Message Transmission
                self.MESSAGE_TRANSMISSION_DELAY_BETWEEN_CHUNKS = fwutils.calc_msg_chunk_interval(agent_conf.get('message_transmission',{}).get('delay_between_chunks', DEFAULT_MESSAGE_TRANSMISSION_DELAY_BETWEEN_CHUNKS))

                # vRouter
                self.VROUTER_API_READ_TIMEOUT = agent_conf.get('vrouter',{}).get('api_read_timeout',  DEFAULT_VROUTER_API_READ_TIMEOUT)

                # Check if config has a valid logical device interface input
                try:
                    device_ip = agent_conf.get('logical_interface_ip')
                    if device_ip:
                        # Validate the input logical interface IP and represent it as a prefix
                        ipaddress.ip_address(device_ip)
                        device_ip += '/32'
                    self.DEVICE_LOGICAL_INTERFACE_IP = device_ip
                except ValueError as e:
                    log.warning('Invalid device logical IP address %s' % str(e))
                    self.DEVICE_LOGICAL_INTERFACE_IP = None

            except Exception as e:
                if log:
                    log.excep("%s, set defaults" % str(e))
                self.BYPASS_CERT    = DEFAULT_BYPASS_CERT
                self.DEBUG          = DEFAULT_DEBUG
                self.MANAGEMENT_URL = DEFAULT_MANAGEMENT_URL
                self.TOKEN_FILE     = DEFAULT_TOKEN_FILE
                self.UUID           = DEFAULT_UUID
                self.DAEMON_SOCKET_NAME                = DEFAULT_DAEMON_SOCKET_NAME
                self.WATCHDOG_DEADLOCK_ENABLED         = DEFAULT_WATCHDOG_DEADLOCK_ENABLED
                self.WAN_MONITOR_UNASSIGNED_INTERFACES = DEFAULT_WAN_MONITOR_UNASSIGNED_INTERFACES
                self.WAN_MONITOR_SERVERS               = DEFAULT_WAN_MONITOR_SERVERS
                self.WAN_MONITOR_PROBE_TIMEOUT         = DEFAULT_WAN_MONITOR_PROBE_TIMEOUT
                self.WAN_MONITORING_WINDOW_SIZE        = DEFAULT_WAN_MONITOR_WINDOW_SIZE
                self.WAN_MONITORING_THRESHOLD          = DEFAULT_WAN_MONITOR_THRESHOLD
                self.FQDN_RESOLUTION_INTERVAL          = DEFAULT_FQDN_RESOLUTION_INTERVAL
                self.LTE_SWITCHOVER_INTERVAL           = DEFAULT_LTE_SWITCHOVER_INTERVAL
                self.LTE_SWITCHOVER_OPERATOR_INTERVAL  = DEFAULT_LTE_SWITCHOVER_OPERATOR_INTERVAL

                self.DAEMON_SOCKET_NAME                = DEFAULT_DAEMON_SOCKET_NAME
                self.WATCHDOG_DEADLOCK_ENABLED         = DEFAULT_WATCHDOG_DEADLOCK_ENABLED
                self.WATCHDOG_CONNECTION_ENABLED       = DEFAULT_WATCHDOG_CONNECTION_ENABLED
                self.WATCHDOG_ROUTER_CFG_WINDOW        = DEFAULT_WATCHDOG_ROUTER_CFG_WINDOW

                self.MESSAGE_TRANSMISSION_DELAY_BETWEEN_CHUNKS = fwutils.calc_msg_chunk_interval(DEFAULT_MESSAGE_TRANSMISSION_DELAY_BETWEEN_CHUNKS)

                self.VROUTER_API_READ_TIMEOUT          = DEFAULT_VROUTER_API_READ_TIMEOUT
            if self.DEBUG and log:
                log.set_level(FWLOG_LEVEL_DEBUG)
            self.debug = None


    class FwCache:
        """Storage for data that is valid during one FwAgent lifecycle only.
        """
        def __init__(self):
            self.db = {
                'LINUX_INTERFACES': {},
                'DEV_ID_TO_VPP_IF_NAME': {},
                'DEV_ID_TO_VPP_TAP_NAME': {},
                'STUN': {},
                'SYMMETRIC_NAT': {},
                'SYMMETRIC_NAT_TUNNELS': {},
                'VPP_IF_NAME_TO_DEV_ID': {},
                'LINUX_INTERFACES_BY_NAME': {},
                'WAN_MONITOR': {
                    'enabled_routes':  {},
                    'disabled_routes': {},
                },
                'LTE': {},
                'PPPOE': {
                    'dev_ids': {},
                    'if_names': {},
                    'vpp_if_names': {},
                },
                'BLACKLIST_INTERFACES': {},
                'THREADS': {
                    'snapshots': {},
                    'thread_to_locks': {},
                    'lock_to_thread': {},
                },
            }
            self.lock                       = FwRlock("FwCache")
            self.linux_interfaces           = self.db['LINUX_INTERFACES']
            self.dev_id_to_vpp_if_name      = self.db['DEV_ID_TO_VPP_IF_NAME']
            self.dev_id_to_vpp_tap_name     = self.db['DEV_ID_TO_VPP_TAP_NAME']
            self.stun_cache                 = self.db['STUN']
            self.sym_nat_cache              = self.db['SYMMETRIC_NAT']
            self.sym_nat_tunnels_cache      = self.db['SYMMETRIC_NAT_TUNNELS']
            self.vpp_if_name_to_dev_id      = self.db['VPP_IF_NAME_TO_DEV_ID']
            self.linux_interfaces_by_name   = self.db['LINUX_INTERFACES_BY_NAME']
            self.wan_monitor                = self.db['WAN_MONITOR']
            self.lte                        = self.db['LTE']
            self.pppoe_dev_ids              = self.db['PPPOE']['dev_ids']
            self.pppoe_if_names             = self.db['PPPOE']['if_names']
            self.pppoe_vpp_if_names         = self.db['PPPOE']['vpp_if_names']
            self.blacklist_interfaces       = self.db['BLACKLIST_INTERFACES']
            self.thread_snapshots           = self.db['THREADS']['snapshots']
            self.thread_to_locks            = self.db['THREADS']['thread_to_locks']
            self.thread_lock_to_thread      = self.db['THREADS']['lock_to_thread']
            self.thread_lock                = threading.Lock()


    def __init__(self, log=None, debug_conf_file=None):
        """Constructor method
        """
        FwObject.__init__(self, log=log)

        self.config = config

        # create directories if not exist/removed by a user
        Path(self.config.folders.logs).mkdir(parents=True, exist_ok=True)
        Path(self.config.folders.data).mkdir(parents=True, exist_ok=True)

        # Root-only runtime directory for volatile data (in-memory DB-s, RPC socket).
        # It replaces the world-writable /dev/shm used in the past.
        self.RUN_PATH = f'/run/{self.config.company}/'
        fw_os_utils.ensure_private_dir(self.RUN_PATH, 0o700)

        # Set default configuration
        self.RETRY_INTERVAL_MIN  = 5 # seconds - is used for both registration and main connection
        self.RETRY_INTERVAL_MAX  = 15
        self.RETRY_INTERVAL_LONG_MIN = 50
        self.RETRY_INTERVAL_LONG_MAX = 70
        self.DATA_PATH           = self.config.folders.data + '/'
        self.DATA_PATH_RAM       = self.RUN_PATH
        self.FWAGENT_CONF_FILE   = self.DATA_PATH + self.config.filenames.agent_conf  # Can be overridden later!
        self.DEBUG_CONF_FILE     = self.DATA_PATH + 'debug_conf.yaml'
        self.DEVICE_TOKEN_FILE   = self.DATA_PATH + self.config.filenames.device_token
        self.VERSIONS_FILE       = self.DATA_PATH + '.versions.yaml'
        self.ROUTER_CFG_FILE     = self.DATA_PATH + '.requests.sqlite'
        self.ROUTER_PENDING_CFG_FILE = self.DATA_PATH + '.requests.pending.sqlite'
        self.SYSTEM_CFG_FILE     = self.DATA_PATH + '.system.sqlite'
        self.APPLICATIONS_CFG_FILE = self.DATA_PATH + '.applications.sqlite'
        self.APPLICATIONS_TRACKER_FILE = self.DATA_PATH_RAM + '.applications.tracker.json'
        self.JOBS_FILE           = self.DATA_PATH + '.jobs.sqlite'
        self.ROUTER_STATE_FILE   = self.DATA_PATH + '.router.state'
        self.CONN_FAILURE_FILE   = self.DATA_PATH + '.upgrade_failed'
        self.IKEV2_FOLDER        = self.DATA_PATH + 'ikev2/'
        self.ROUTER_LOG_FILE          = self.config.folders.logs + '/agent.log'
        self.HUGE_LINE_LOG_FILE       = self.config.folders.logs + '/agent.huge_lines.log'
        self.APPLICATION_IDS_LOG_FILE = self.config.folders.logs + '/application_ids.log'
        self.FIREWALL_LOG_FILE        = self.config.folders.logs + '/firewall.log'
        self.AGENT_UI_LOG_FILE        = self.config.folders.logs + '/agentui.log'
        self.SYSTEM_CHECKER_LOG_FILE  = self.config.folders.logs + '/system_checker.log'
        self.PROFILE_LOG_FILE         = self.config.folders.logs + '/profile.log'
        self.REPO_SOURCE_DIR     = '/etc/apt/sources.list.d/'
        self.HOSTAPD_LOG_FILE     = '/var/log/hostapd.log'
        self.HOSTAPD_LOG_FILE_BACKUP = '/var/log/hostapd.log.backup'
        self.SYSLOG_FILE         = '/var/log/syslog'
        self.DHCP_LOG_FILE       = '/var/log/kea/kea-dhcp4.log'
        self.VPP_LOG_FILE        = '/var/log/vpp/vpp.log'
        self.FRR_LOG_FILE       = '/var/log/frr/ospfd.log'
        self.VPP_CONFIG_FILE     = '/etc/vpp/startup.conf'
        self.VPP_CONFIG_FILE_BACKUP   = '/etc/vpp/startup.conf.baseline'
        self.VPP_CONFIG_FILE_RESTORE = '/etc/vpp/startup.conf.orig'
        self.VPP_TRACE_FILE_EXT  = '.vpp.api'
        self.FRR_ZEBRA_FILE      = '/etc/frr/zebra.conf'
        self.FRR_DAEMONS_FILE    = '/etc/frr/daemons'
        self.FRR_CONFIG_FILE     = '/etc/frr/frr.conf'
        self.FRR_OSPFD_FILE      = '/etc/frr/ospfd.conf'
        self.FRR_BGPD_FILE      = '/etc/frr/bgpd.conf'
        self.FRR_STATICD_FILE   = '/etc/frr/staticd.conf'
        self.FRR_VTYSH_FILE      = '/etc/frr/vtysh.conf'
        self.FRR_VTYSH_FILE_TMP  = '/tmp/frr.tmp'
        self.FRR_OSPF_ACL       = f'{self.config.frr.config_prefix}-redist-ospf-acl'
        self.FRR_OSPF_ROUTE_MAP = f'{self.config.frr.config_prefix}-redist-ospf-rm'
        self.FRR_BGP_ACL       = f'{self.config.frr.config_prefix}-redist-bgp-acl'
        self.FRR_BGP_ROUTE_MAP = f'{self.config.frr.config_prefix}-redist-bgp-rm'
        self.FRR_LAN_NAT_ROUTE_ACL = f"{self.config.frr.config_prefix}-redist-lan-nat-acl"
        self.FRR_LAN_NAT_ROUTE_MAP = f"{self.config.frr.config_prefix}-redist-lan-nat-rm"
        self.KEA_DHCP_CONFIG_FILE = '/etc/kea/kea-dhcp4.conf'
        self.KEA_DHCP_CONFIG_FILE_BACKUP = f'/etc/kea/kea-dhcp4.conf.{self.config.dhcp_server.backup_extension}'
        self.KEA_DHCP_CONFIG_FILE_TMP = '/tmp/kea-dhcp4.tmp'
        self.KEA_DHCP_LEASE_DB_FILE = '/var/lib/kea/dhcp4.leases'
        self.PPPOE_CONFIG_PATH   = '/etc/ppp/'
        self.PPPOE_CONFIG_PROVIDER_FILE   = self.config.pppoe.provider_filename
        self.FRR_DB_FILE         = self.DATA_PATH + '.frr.sqlite'
        self.PPPOE_DB_FILE       = self.DATA_PATH + '.pppoe.sqlite'
        self.POLICY_REC_DB_FILE  = self.DATA_PATH + '.policy.sqlite'
        self.MULTILINK_DB_FILE   = self.DATA_PATH + '.multilink.sqlite'
        self.FIREWALL_DB_FILE    = self.DATA_PATH + '.firewall.sqlite'
        self.FQDN_RESOLVER       = self.DATA_PATH + '.fqdn_resolver.sqlite'
        self.DATA_DB_FILE        = self.DATA_PATH + '.data.sqlite'
        self.TRAFFIC_ID_DB_FILE  = self.DATA_PATH + '.traffic_identification.sqlite'
        self.QOS_DB_FILE         = self.DATA_PATH + '.qos.sqlite'
        self.DATA_MEMDB_FILE     = self.DATA_PATH_RAM + 'memdb.sqlite'
        self.HOSTAPD_CONFIG_DIRECTORY = '/etc/hostapd/'
        self.NETPLAN_FILES       = {}
        self.NETPLAN_FILE        = f'/etc/netplan/99-{self.config.netplan.filename_prefix}.{self.config.exec_file_suffix}.yaml'
        self.NETPLAN_RECOVERY_FILE_STANDBY= f'/etc/netplan/{self.config.netplan.filename_prefix}.yaml.recovery'
        self.NETPLAN_RECOVERY_FILE_ACTIVE = f'/etc/netplan/{self.config.netplan.filename_prefix}.recovery.yaml'
        self.NETPLAN_RECOVERY_FILE_SILENCED = f'/etc/netplan/{self.config.netplan.filename_prefix}.recovery.silenced'
        self.NETPLAN_RECOVERY_BAD_FILE_EXT= '.disabled_by_recovery'
        self.WS_STATUS_NOT_APPROVED       = 403
        self.WS_TIMEOUT                   = 180 # seconds, if no requests were received in X seconds - reconnect
        self.fwagent = None
        self.pppoe = None
        self.modems = None
        self.loadsimulator = None
        self.routes = None
        self.router_api = None
        self.statistics = None
        self.cache   = self.FwCache()
        self.WAN_FAILOVER_WND_SIZE         = 20         # 20 pings, every ping waits a second for response
        self.WAN_FAILOVER_THRESHOLD        = 12         # 60% of pings lost - enter the bad state, 60% of pings are OK - restore to good state
        self.WAN_FAILOVER_METRIC_WATERMARK = 2000000000 # Bad routes will have metric above 2000000000
        self.DEVICE_LOGICAL_INTERFACE     =  16383 # Last in the range used for device logical interface configuration
        self.LOOPBACK_ID_LAN_NAT          =  16382 # Last before used for LAN NAT loopback interface configuration
        self.LOOPBACK_ID_SWITCHES          = [16300, 16381] # Loopback id in vpp is up to 16384, so we use this range for switch feature
        self.LOOPBACK_ID_LOGICAL_INTERFACE = [16290, 16299] # Loopback ids for Edge virtual/logical interfaces
        self.LOOPBACK_ID_TUNNELS           = [1, 16289]  # Loopback id in vpp is up to 16289, so we use this range for tunnels
        self.DUMP_FOLDER                   = f'{self.config.folders.logs}/{self.config.commands.dump.cmd}'
        self.DEFAULT_DNS_SERVERS           = ['8.8.8.8', '8.8.4.4']
        self.router_threads                = FwRouterThreading() # Primitives used for synchronization of router configuration and monitoring threads
        self.handle_request_lock           = FwRlock("handle_request_lock")
        self.is_gcp_vm                     = fwutils.detect_gcp_vm()
        self.default_vxlan_port            = 4789
        self.DEADLOCK_PROBE_INTERVAL       = 5   # seconds, between snapshot-ing thread frames
        self.DEADLOCK_THRESHOLD_PROBES     = 60  # number of probes before deadlock recovery is triggered
        self.MESSAGE_HANDLER_QUEUE_TIMEOUT = 300 # 5 min for waiting for system to execute received request
        self.MAX_PENDING_REPLIES           = 5   # 5 job replies to save and re-send on socket reconnect
        self.agent_initialized             = False

        # Config limit for QoS scheduler memory usage (limits to 'x' % of configured VPP memory)
        self.QOS_SCHED_MAX_MEMORY_PERCENT = 5

        if log:
            log.set_huge_line_file(self.HUGE_LINE_LOG_FILE)

        # Load configuration from file
        self.cfg = self.FwConfiguration(self.FWAGENT_CONF_FILE, self.DATA_PATH, log=log)
        self.load_debug_configuration_from_file(debug_conf_file if debug_conf_file else self.DEBUG_CONF_FILE)

        self._set_daemon_socket(self.cfg.DAEMON_SOCKET_NAME)

        self.sqlite_dicts = {}

        # IMPORTANT! set the db variable regardless of agent initialization
        self.db = self.create_sqlite_dict(self.DATA_DB_FILE)
        self.memdb = self.create_sqlite_dict(self.DATA_MEMDB_FILE)

        # Load signal to string map
        self.signal_names = dict((getattr(signal, n), n) \
                                for n in dir(signal) if n.startswith('SIG') and '_' not in n )

        # Load cli modules
        #
        root_dir = os.path.dirname(os.path.realpath(__file__))
        for cmd_name, cli_command in cli_commands.items():
            cli_command_files = glob.glob(f'{root_dir}/cli/fwcli_{cmd_name}*.py')
            for filename in cli_command_files:
                cli_module_name = os.path.splitext(os.path.basename(filename))[0] # .../cli/fwcli_configure_router.py -> "fwcli_configure_router"
                cli_command['modules'].append(cli_module_name)
                cli_import = __import__(f'cli.{cli_module_name}')
                cli_module = getattr(cli_import, cli_module_name)
                cli_modules.update({cli_module_name: cli_module})

    def _set_daemon_socket(self, daemon_socket):
        """Set the path of the unix socket used for RPC to the agent daemon.
        The RPC must not be served on TCP socket, as any local user/service could
        use it to run code as root. Therefore only socket files located in
        the root-only runtime directory (RUN_PATH) are accepted. The legacy
        'host:port' values of the 'daemon_socket' option in fwagent_conf.yaml
        are ignored and the default unix socket is used instead.
        """
        default_socket = self.RUN_PATH + 'fwagent.sock'
        daemon_socket  = str(daemon_socket) if daemon_socket else default_socket
        socket_name    = daemon_socket[len(self.RUN_PATH):] if daemon_socket.startswith(self.RUN_PATH) else ''
        if not socket_name or '/' in socket_name or socket_name.startswith('.'):
            if self.log:
                self.log.debug(f"daemon_socket '{daemon_socket}' is not supported, use unix socket {default_socket}")
            daemon_socket = default_socket
        self.FWAGENT_DAEMON_SOCKET = daemon_socket
        self.FWAGENT_DAEMON_NAME   = f'{self.config.commands.agent.cmd}.daemon'
        self.FWAGENT_DAEMON_URI    = 'PYRO:%s@./u:%s' % (self.FWAGENT_DAEMON_NAME, self.FWAGENT_DAEMON_SOCKET)

    def finalize(self):
        for sqlite_dict in self.sqlite_dicts.values():
            sqlite_dict.finalize()
        self.sqlite_dicts = {}

    def load_configuration_from_file(self):
        """Load configuration from YAML file.

        :returns: None.
        """
        # Store aside parameters that we don't want to be overrode
        debug_cfg = self.cfg.debug
        # Load configuration
        self.cfg.__init__(self.FWAGENT_CONF_FILE, self.DATA_PATH)
        # Restore parameter that we don't want to be overrode
        self.cfg.debug = debug_cfg
        # Print loaded configuration into log
        if self.cfg.DEBUG:
            self.log.debug("Fwglobals configuration: " + self.__str__(), to_terminal=False)
            # for a in dir(self.cfg):
            #     val = getattr(self, a)
            #     if isinstance(val, (int, float, str, unicode)):
            #         log.debug("  %s: %s" % (a, str(val)), to_terminal=False)
            # for a in dir(self):
            #     val = getattr(self, a)
            #     if isinstance(val, (int, float, str, unicode)):
            #         log.debug("  %s: %s" % (a, str(val)), to_terminal=False)

    def load_debug_configuration_from_file(self, debug_conf_file):
        """Load debug configuration from YAML file.

        :returns: None.
        """
        # First of all load default values on the very first call.
        # That makes an accessing code a bit more nice, as it won't need to check filed existence.
        #
        if self.cfg.debug is None:
            self.cfg.debug = {
                'daemon': {
                    'standalone': False,
                },
                'agent': {
                    'features': {
                        'pppoe': {
                            'enabled': True
                        },
                        'stun': {
                            'enabled': True
                        },
                        'wan_monitor': {
                            'enabled': True
                        },
                        'autosense': {
                            'enabled': bool(os.path.exists('/usr/bin/fwautosense'))
                        }
                    },
                    'requests': {
                        'ignored': [],
                    }
                },
                'network': {
                    'debugger_interface': {
                        'ethernets': {}
                    }
                },
                'profiling': {
                    'enabled': False,
                    'exec_timeout': 30,
                    'print_lines': 10
                }
            }

        if not os.path.isfile(debug_conf_file):
            # The default file might not exist - we do not expose it to users.
            if debug_conf_file != self.DEBUG_CONF_FILE:
                raise Exception(f"load_debug_configuration_from_file: {debug_conf_file} not found")
            return

        with open(debug_conf_file, 'r') as debug_conf_file:
            loaded = yaml.load(debug_conf_file, Loader=yaml.SafeLoader)
            fwutils.dict_deep_update(self.cfg.debug, loaded)

    def load_agent_configuration_from_file(self, filename):
        if not os.path.exists(filename):
            raise Exception(f"load_agent_configuration_from_file: {filename} not found")

        if self.FWAGENT_CONF_FILE != filename:
            self.log.debug(f'load_agent_configuration_from_file({filename}): conf file changed from {self.FWAGENT_CONF_FILE} to {filename}')
            self.FWAGENT_CONF_FILE = filename
            self.load_configuration_from_file()

    def create_sqlite_dict(self, filename, table_name="", autocommit=True):
        '''This function is needed to track all opened SqliteDict files.
        That enables us to close all SqliteDicts at the end of shutdown,
        after finalization all other objects and stopping all other threads.
        In this way we ensure that no one accesses SqliteDict after its closure,
        thus preventing hang of SqliteDict internal thread that serves queries.
        '''
        key = filename + table_name
        if not key in self.sqlite_dicts:
            sqlite_dict = FwSqliteDict(filename, table_name=table_name, autocommit=autocommit)
            sqlite_dict.initialize()
            self.sqlite_dicts.update({key: sqlite_dict})
        return self.sqlite_dicts[key]

    def create_agent(self):
        """Create the fwagent and the rest of supporting objects (that are globals for historical reasons).
        """
        if self.fwagent:
            self.log.warning('create_agent(): agent exists')
            return self.fwagent

        # Create loggers
        #
        self.logger_add_application         = FwObjectLogger('add_application',     log=FwLogFile(filename=self.APPLICATION_IDS_LOG_FILE,   level=log.level))
        self.logger_add_firewall_policy     = FwObjectLogger('add_firewall_policy', log=FwLogFile(filename=self.FIREWALL_LOG_FILE,          level=log.level))
        self.loggers = {
            'add-application':        self.logger_add_application,
            'remove-application':     self.logger_add_application,
            'add-firewall-policy':    self.logger_add_firewall_policy,
            'remove-firewall-policy': self.logger_add_firewall_policy,
        }
        self.logger_devnull = FwObjectLogger('/dev/null',  log=FwLogDevNull())


        # Some lte modules have a problem with drivers binding.
        # As workaround, we reload the driver to fix it.
        # We run it only if vpp is not running to make sure that we reload the driver
        # only on boot, and not if a user run `systemctl restart flexiwan-router` when vpp is running.
        if not fw_os_utils.vpp_does_run():
            fwlte.reload_lte_drivers_if_needed()

        self.notifications    = FwNotifications()
        self.dhcp_server      = FwDhcpServer()
        self.fqdn_resolver    = FwFqdnResolver()
        self.fwagent          = FwAgent(handle_signals=False)
        self.router_cfg       = FwRouterCfg(self.ROUTER_CFG_FILE) # IMPORTANT! Initialize database at the first place!
        self.system_cfg       = FwSystemCfg(self.SYSTEM_CFG_FILE)
        self.jobs             = FwJobs(self.JOBS_FILE)
        self.agent_api        = FWAGENT_API()
        self.system_api       = FWSYSTEM_API(self.system_cfg)
        self.router_api       = FWROUTER_API(self.router_cfg, self.ROUTER_PENDING_CFG_FILE, self.MULTILINK_DB_FILE, self.FRR_DB_FILE)
        self.applications_api = FWAPPLICATIONS_API()
        self.os_api           = OS_API()
        self.policies         = FwPolicies(self.POLICY_REC_DB_FILE)
        self.wan_monitor      = FwWanMonitor()
        self.stun_wrapper     = FwStun()
        self.ikev2            = FwIKEv2()
        self.pppoe            = FwPppoeClient()
        self.modems           = fwlte.FwModemManager()
        self.routes           = FwRoutes()
        self.qos              = FwQoS()
        self.statistics       = FwStatistics()
        self.traffic_identifications = FwTrafficIdentifications(self.TRAFFIC_ID_DB_FILE, logger=self.logger_add_application)
        self.message_handler  = FwMessageHandler()
        self.watchdog         = FwWatchdog()
        self.nat_manager      = FwNatSessionsManager(cache_timeout=120)

        fwutils.set_default_linux_reverse_path_filter(2)  # RPF set to Loose mode
        fwutils.disable_ipv6()

        # Increase allowed multicast group membership from default 20 to 4096
        # OSPF need that to be able to discover more neighbors on adjacent links
        fwutils.set_linux_igmp_max_memberships(4096)

        # Set sys params to setup VPP coredump
        fw_vpp_coredump_utils.vpp_coredump_sys_setup()

        # Increase allowed max socket receive buffer size to 16Mb
        # VPPSB need that to handle more netlink events on a heavy load
        fwutils.set_linux_socket_max_receive_buffer_size(16777216)

        # Increase max open file descriptors size to 16384 to avoid issue "Too many open files"
        fwutils.set_linux_max_open_file_descriptor_size(16384)

        # Increase ARP table size to avoid DNS resolution failures on scale
        fwutils.set_linux_arp_table_size()

        # On the first agent start stop the recovery mode.
        # Remember, recovery yaml-s have static addresses. So, if the device was in recovered mode
        # in other location, which means the recovery yaml-s were in use, and now it is powered on
        # at the new location, the recovery yaml-s might not match the network, thus breaking
        # the connectivity. To prevent this, we disable recovery yaml-s and give the recovery
        # mechanism to enable them back later if needed.
        #
        # IMPORTANT: do this before agent initialization, as FWROUTER_API messes with yaml-s on
        # initialization.
        #
        vpp_runs = fw_os_utils.vpp_does_run()
        if not vpp_runs:
            from fwnetplan import stop_recovery_netplan
            stop_recovery_netplan()

        self.initialize_agent()
        return self.fwagent

    def destroy_agent(self):
        """Graceful shutdown...
        """
        self.finalize_agent()

        del self.watchdog
        del self.message_handler
        del self.routes
        del self.pppoe; self.pppoe = None
        del self.modems
        del self.statistics; self.statistics = None
        del self.wan_monitor
        del self.stun_wrapper
        del self.policies
        del self.traffic_identifications
        del self.os_api
        del self.router_api
        del self.agent_api
        del self.applications_api
        del self.logger_add_application
        del self.fwagent
        self.fwagent = None

    def initialize_agent(self):
        """Restore VPP if needed and start various features.
        """
        self.log.debug('initialize_agent: started')

        # IMPORTANT! Some of the features below should be initialized before router_api.initialize()
        #
        self.fwagent.initialize()
        self.router_cfg.initialize()
        self.pppoe.initialize()
        self.fqdn_resolver.initialize()
        self.modems.initialize(restore_lte_configuration=True)
        self.stun_wrapper.initialize()

        self.router_api.initialize()

        # IMPORTANT! Some of the features below should be initialized after router_api.initialize()
        #
        self.wan_monitor.initialize()
        self.system_api.initialize()  # This one does not depend on VPP :)
        self.routes.initialize()
        self.applications_api.initialize()
        self.statistics.initialize()
        self.qos.initialize()
        self.message_handler.initialize()

        self.watchdog.start()

        self.agent_initialized = True
        self.log.debug('initialize_agent: completed')

    def finalize_agent(self):
        self.log.debug('finalize_agent: started')
        self.router_threads.teardown = True   # Stop all threads in parallel to speedup gracefull exit
        self.agent_initialized       = False
        try:
            self.watchdog.stop()
            if self.message_handler.initialized:
                self.message_handler.finalize()
            if self.qos.initialized:
                self.qos.finalize()
            if self.routes.initialized:
                self.routes.finalize()
            if self.pppoe.initialized:
                self.pppoe.finalize()
            if self.fqdn_resolver.initialized:
                self.fqdn_resolver.finalize()
            if self.statistics.initialized:
                self.statistics.finalize()
            if self.wan_monitor.initialized:
                self.wan_monitor.finalize()
            if self.stun_wrapper.initialized:
                self.stun_wrapper.finalize()
            if self.system_api.initialized:
                self.system_api.finalize()
            if self.router_api.initialized:
                self.router_api.finalize()
            if self.applications_api.initialized:
                self.applications_api.finalize()
            if self.modems.initialized:
                self.modems.finalize()
            if self.fwagent.initialized:
                self.fwagent.finalize()
            if self.router_cfg.initialized:
                self.router_cfg.finalize() # IMPORTANT! Finalize database at the last place!
        except Exception as e:
            self.log.excep(f"finalize_agent: {str(e)}: {traceback.format_exc()}")
        self.log.debug('finalize_agent: completed')

    def __str__(self):
        """Get string representation of configuration.

        :returns: String in JSON format.
        """
        return json.dumps({
            'MANAGEMENT_URL':       self.cfg.MANAGEMENT_URL,
            'TOKEN_FILE':           self.cfg.TOKEN_FILE,
            'BYPASS_CERT':          self.cfg.BYPASS_CERT,
            'DEBUG':                self.cfg.DEBUG,
            'UUID':                 self.cfg.UUID,
            'FWAGENT_CONF_FILE':    self.FWAGENT_CONF_FILE,
            'RETRY_INTERVAL_MIN':   self.RETRY_INTERVAL_MIN,
            'RETRY_INTERVAL_MAX':   self.RETRY_INTERVAL_MAX,
            }, indent = 2)

    def _call_agent_api(self, request):
        return self.agent_api.call(request)

    def _call_system_api(self, request):
        return self.system_api.call(request)

    def _call_router_api(self, request):
        return self.router_api.call(request)

    def _call_os_api(self, request):
        return self.os_api.call_simple(request)

    def _call_applications_api(self, request):
        return self.applications_api.call(request)

    def _call_cli_command(self, request):
        cli_module_name = request['cli_module_name']
        cli_func_name   = request['cli_func_name']
        cli_func_params = request['params']

        f = getattr(cli_modules[cli_module_name], cli_func_name)
        ret = f(**cli_func_params)

        # To be aligned with infrastructure that handles requests from flexiManage,
        # implementation of CLI command should return following object:
        #   {
        #       'ok':  [ 0|1 ],
        #       'ret': [ <serializable object> | <error string> ]
        #   }
        # To make life of developers a bit easier, we enable the command functions
        # to return anything, and then we format it as needed:
        #
        if ret is None:
            return {'ok': 1}
        if not isinstance(ret, dict) or 'ret' not in ret:
            return {'ok': 1, "ret": ret}
        return ret

    def inject_request(self, request, activity=""):
        """Handle injected (not originated from flexiManage) request.

        :param request:          The received request
        :param activity:         The originating activity (e.g., restore VPP after reboot).

        :returns: Dictionary with error string and status code.
        """

        system_job_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        system_job_id = 'system_' + system_job_id
        self.log.debug(f'===={system_job_id}: started===')

        self.jobs.start_recording(system_job_id, request, activity)
        reply = self.handle_request(request)
        self.jobs.stop_recording(system_job_id, { 'ok': reply['ok']})

        self.log.debug(f'===={system_job_id}: finished===')
        return reply

    def handle_request(self, request, original_request=None, lock_system=True):
        """Handle request received from flexiManage or injected locally.

        :param request:          The request received from flexiManage after
                                 transformation by fwutils.fix_received_message().
        :param original_request: The original request received from flexiManage.

        :returns: Dictionary with error string and status code.
        """
        try:
            if lock_system:
                self.handle_request_lock.acquire()

            req    = request['message']
            handler      = request_handlers.get(req)
            handler_func = getattr(self, handler.get('name'))

            reply = handler_func(request)
            if reply['ok'] == 0:
                vpp_trace_file = fwutils.build_timestamped_filename('',self.VPP_TRACE_FILE_EXT)
                os.system('sudo vppctl api trace save %s' % (vpp_trace_file))
                raise Exception(reply['message'])

            # On router configuration request, e.g. add-interface,
            # remove-tunnel, etc. update the configuration database
            # signature. This is needed to assists the database synchronization
            # feature that keeps the configuration set by user on the flexiManage
            # in sync with the one stored on the flexiEdge device.
            # Note we update signature on configuration requests received from flexiManage only,
            # but retrieve it into replies for all requests. This is to simplify
            # flexiManage code.
            #
            if reply['ok'] == 1 and handler.get('sign') and original_request:
                fwutils.update_device_config_signature(original_request)
            reply['router-cfg-hash'] = fwutils.get_device_config_signature()

        except Exception as e:
            global log
            err_str = "%s(%s): %s" % (req, format(fw_redact.redact(request.get('params'))), str(e))
            if isinstance(e, fw_os_utils.CalledProcessSigTerm):
                log.debug(err_str)
            else:
                log.error(err_str + ': %s' % str(traceback.format_exc()))
            reply = {'message': str(e), 'ok': 0}

        finally:
            if lock_system:
                self.handle_request_lock.release()
            return reply

    def _get_api_object_attr(self, api_type, attr):
        if api_type == '_call_router_api':
            return getattr(self.router_api, attr)
        elif api_type == '_call_system_api':
            return getattr(self.system_api, attr)
        elif api_type == '_call_applications_api':
            return getattr(self.applications_api, attr)

    def _call_aggregated(self, request):
        """Handle aggregated request from flexiManage.

        :param request: the aggregated request like:
            {
                "entity": "agent",
                "message": "aggregated",
                "params": {
                    "requests": [
                        {
                            "entity": "agent",
                            "message": "remove-lte",
                            "params": {
                                "apn": "we",
                                "enable": false,
                                "dev_id": "usb:usb1/1-3/1-3:1.4"
                            }
                        },
                        {
                            "entity": "agent",
                            "message": "remove-interface",
                            "params": {
                                "dhcp": "yes",
                                "addr": "10.93.172.31/26",
                                "addr6": "fe80::b82a:beff:fe44:38e8/64",
                                "PublicIP": "46.19.85.31",
                                "PublicPort": "4789",
                                "useStun": true,
                                "monitorInternet": true,
                                "gateway": "10.93.172.32",
                                "metric": "",
                                "routing": "NONE",
                                "type": "WAN",
                                "configuration": {
                                    "apn": "we",
                                    "enable": false
                                },
                                "deviceType": "lte",
                                "dev_id": "usb:usb1/1-3/1-3:1.4",
                                "multilink": {
                                    "labels": []
                                }
                            }
                        }
                    ]
                }
            }

        :returns: dictionary with status code and optional error message.
        """
        # Break the received aggregated request into aggregations by API type
        #
        # !!! IMPORTANT !!!
        # ATM we decided to run system-api requests before router-api requests.
        #
        aggregations = {}
        for _request in request['params']['requests']:

            handler = request_handlers.get(_request['message'])
            assert handler, '"%s" request is not supported' % _request['message']

            api = handler.get('name')
            assert api, 'api for "%s" not found' % _request['message']

            # Create the aggregations for the current API type, if it was not created yet.
            #
            if not api in aggregations:
                aggregations[api] = {
                    "message": "aggregated",
                    "params": {
                        "requests": []
                    }
                }

            # Finally add the current request to the current aggregation.
            #
            aggregations[api]['params']['requests'].append(_request)


        # Now generate the rollback aggregated requests for the aggregations created above.
        # We need them in case of failure to execute any of the created requests,
        # as we have to revert the previously executed request. This is to ensure
        # atomic handling of the original aggregated request received from flexiManage.
        #
        rollback_aggregations = self._build_rollback_aggregations(aggregations)

        # Go over list of aggregations and execute their requests one by one.
        #
        executed_apis = []
        for api in ['_call_system_api', '_call_router_api', '_call_applications_api']:
            if api in aggregations:
                api_call_func = self._get_api_object_attr(api, 'call')
                try:
                    api_call_func(aggregations[api])
                    executed_apis.append(api)
                except Exception as e:
                    # Revert the previously executed aggregated requests
                    for api in executed_apis:
                        rollback_func = self._get_api_object_attr(api, 'rollback')
                        rollback_func(rollback_aggregations[api])
                    raise e

        return {'ok': 1}


    def _build_rollback_aggregations(self, aggregations):
        '''Generates rollback data for the list of aggregated requests grouped by type of api they belong to.
        The input list format is:
            {
                <api name, e.g. "router_api", "system_api", etc>:
                    {
                        "message": "aggregated",
                        "params": {
                            "requests": [ ... ]
                        }
                    }
                }
                ,
                ...
            }

        The output rollback data represents clone of the input list, where the leaf requests
        (requests in list element['params']['requests'])
        perform opposite operation. That means, the "add-X" is replaced with
        "remove-X", the "remove-X" is replaced with "add-X", and parameters of the "modify-X"
        are replaced with the old parameters that are currently stored in the configuration database.
        '''
        rollbacks_aggregations = copy.deepcopy(aggregations)
        for (api, aggregated) in list(rollbacks_aggregations.items()):
            cfg_db = self._get_api_object_attr(api, 'cfg_db')
            for request in aggregated['params']['requests']:

                op = request['message']
                if re.match('add-', op):
                    request['message'] = op.replace('add-','remove-')

                elif re.match('start-', op):
                    request['message'] = op.replace('start-','stop-')

                elif re.match('stop-', op):
                    request['message'] = op.replace('stop-','start-')

                elif re.match('remove-', op):
                    request['message'] = op.replace('remove-','add-')
                    # The "remove-X" might have only subset of configuration parameters.
                    # To ensure proper rollback, populate the correspondent "add-X" with
                    # full set of configuration parameters. They are stored in database.
                    #
                    request['params'] = cfg_db.get_request_params(request)
                    if request['params'] == None:
                        request['params'] = {} # Take a care of removal of not existing configuration item

                elif re.match('modify-', op):
                    # For "modify-X" replace it's parameters with the old parameters,
                    # that are currently stored in the configuration database.
                    #
                    old_params = cfg_db.get_request_params(request)
                    for param_name in list(request['params']): #request['params'].keys() doesn't work in python 3
                        if old_params and param_name in old_params:
                            request['params'][param_name] = old_params[param_name]
                        else:
                            del request['params'][param_name]
                else:
                    raise Exception("_build_rollback_aggregations: not expected request: %s" % op)

        return rollbacks_aggregations

    def get_logger(self, request):
        if type(request) == list:
            requests = request   # Accommodate to call by update_device_config_signature()
        elif re.match('aggregated|sync-device', request['message']):
            requests = request['params']['requests']
        else:
            requests = [request]

        for r in requests:
            if r['message'] in self.loggers:
                return self.loggers[r['message']]
        return None

    def get_object_func(self, object_name, func_name):
        try:
            if object_name == 'fwglobals.g':
                func = getattr(self, func_name)
            elif object_name == 'fwglobals.g.router_api':
                func = getattr(self.router_api, func_name)
            elif object_name == 'fwglobals.g.router_api.vpp_api':
                func = getattr(self.router_api.vpp_api, func_name)
            elif object_name == 'fwglobals.g.router_api.frr':
                func = getattr(self.router_api.frr, func_name)
            elif object_name == 'fwglobals.g.router_api.multilink':
                func = getattr(self.router_api.multilink, func_name)
            elif object_name == 'fwglobals.g.ikev2':
                func = getattr(self.ikev2, func_name)
            elif object_name == 'fwglobals.g.traffic_identifications':
                func = getattr(self.traffic_identifications, func_name)
            elif object_name == 'fwglobals.g.pppoe':
                func = getattr(self.pppoe, func_name)
            elif object_name == 'fwglobals.g.applications_api':
                func = getattr(self.applications_api, func_name)
            elif object_name == 'fwglobals.g.qos':
                func = getattr(self.qos, func_name)
            elif object_name == 'fwglobals.g.stun_wrapper':
                func = getattr(self.stun_wrapper, func_name)
            elif object_name == 'fwglobals.g.jobs':
                func = getattr(self.jobs, func_name)
            elif object_name == 'fwglobals.g.modems':
                func = getattr(self.modems, func_name)
            elif object_name == 'fwglobals.g.dhcp_server':
                func = getattr(self.dhcp_server, func_name)
            elif object_name == 'fwglobals.g.fqdn_resolver':
                func = getattr(self.fqdn_resolver, func_name)
            else:
                return None
        except Exception as e:
            self.log.excep(f"get_object_func({object_name}, {func_name}): {str(e)}")
            return None
        return func

def initialize(log_level=FWLOG_LEVEL_INFO, quiet=False, debug_conf_file=None):
    """Initialize global instances of LOG, and GLOBALS.

    :param log_level:    LOG severity level.

    :returns: None.
    """
    global g_initialized
    if not g_initialized:
        global log
        log = FwLogSyslog(log_level)
        if quiet:
            log.set_target(to_terminal=False)
        global g
        g = Fwglobals(log=log, debug_conf_file=debug_conf_file)
        g_initialized = 1
    else:
        g_initialized += 1

def finalize():
    global g_initialized
    if g_initialized:
        g_initialized -= 1
        if g_initialized == 0:
            global g
            g.finalize()
            del g
            global log
            del log
