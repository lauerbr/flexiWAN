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

import signal
def fwagent_signal_handler(signum, frame):
    """Handle SIGINT (CTRL+C) to suppress backtrace print onto screen,
	   when invoked by user from command line and not as a daemon.
       Do it ASAP, so CTRL+C in the middle of importing the third-parties
       will not cause the backtrace to print.
	"""
    exit(1)
signal.signal(signal.SIGINT, fwagent_signal_handler)

import fnmatch
import json
import os
import glob
import ssl
import socket
import struct
import sys
import random
import time
try:
    import psutil
    assert psutil   # the import verifies the python environment, psutil is used by other modules
except Exception:
    print("failed to load psutil, ensure you use python 3.8 or later")
    sys.exit(1)
import Pyro4
import re
import subprocess
import threading
import traceback
import yaml
import jwt

from urllib import request as ureq
from urllib import parse as uparse
from urllib import error as uerr
from http import server as hsvr

import fwglobals
import fwikev2
import fwlte
import fwmultilink
import fw_os_utils
import fw_redact
import fw_input_validation
import fwpppoe
import fwrouter_cfg
import fwthread
import fwutils
import fwwebsocket
import fwqos
from fwfirewall import FwFirewall

from fwapplications_api import FWAPPLICATIONS_API
from fwfrr import FwFrr
from fwobject import FwObject

system_checker_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tools/system_checker/")
sys.path.append(system_checker_path)
import fwsystem_checker_common

class FwAgent(FwObject):
    """This class implements abstraction of mediator between manager called
    flexiManage and device called flexiEdge. The manager runs on remote server,
    the Fwagent runs on device. The Fwagent establishes protected connection
    to the manager and starts infinite message handling loop. It receives
    message, called request, invokes global message handler that routes
    the request to the appropriate request handler, takes response
    returned by the message handler and sends it back to the manager.
    Only one request can be processed at any time.
    The global message handler sits in the Fwglobals module.

    :param handle_signals: A flag to handle system signals
    """
    def __init__(self, handle_signals=True):
        """Constructor method
        """
        FwObject.__init__(self)

        self.versions             = fwutils.get_device_versions(fwglobals.g.VERSIONS_FILE)
        self.reconnecting         = False
        self.start_stop_router_seq = None
        self.connection_thread    = None

        self.ws = fwwebsocket.FwWebSocketClient(
                                    on_open    = self._on_open,
                                    on_close   = self._on_close)

        if handle_signals:
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)


    def _signal_handler(self, signum, frame):
        """Signal handler for CTRL+C

        :param signum:         Signal type
        :param frame:          Stack frame.

        :returns: None.
        """
        self.log.info("got %s" % fwglobals.g.signal_names[signum])
        self.__exit__(None, None, None)
        exit(1)

    def initialize(self):
        super().initialize()

    def finalize(self):
        self.ws.finalize()
        super().finalize()

    def _is_allowed_token_url(self, url):
        """Check the URL received in the 'server' or 'repo' claim of the token.
        The agent can't verify the token signature (it has no secret), so the claims
        are not trusted: require HTTPS (HTTP is allowed only if 'bypass_certificate'
        is set explicitly in fwagent_conf.yaml for development setups), and if
        'token_allowed_hosts' is configured in fwagent_conf.yaml, the host must match
        one of its patterns (e.g. '*.flexiwan.com').
        """
        if not isinstance(url, str) or not url or fw_input_validation.has_control_chars(url) or \
           any(c in url for c in ' "\'`$\\'):
            return False
        try:
            parsed = uparse.urlparse(url)
            host = parsed.hostname
        except ValueError:
            return False
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and fwglobals.g.cfg.BYPASS_CERT):
            self.log.error(f"token: URL {url} must use https")
            return False
        if not host or not fw_input_validation.is_valid_host(host):
            return False
        allowed_hosts = fwglobals.g.cfg.TOKEN_ALLOWED_HOSTS
        if allowed_hosts and not any(fnmatch.fnmatch(host.lower(), str(p).lower()) for p in allowed_hosts):
            self.log.error(f"token: host {host} is not in token_allowed_hosts {allowed_hosts}")
            return False
        return True

    def _setup_repository(self, repo):
        # Extract repo info. e.g. 'https://deb.flexiwan.com|flexiWAN|main'
        repo_split = repo.split('|')
        if len(repo_split) != 3:
            self.log.error("Registration error: Incorrect repository info %s" % (repo))
            return False
        repo_server, repo_repo, repo_name = repo_split[0], repo_split[1], repo_split[2]
        # The values are written into apt source file, so validate them
        if not self._is_allowed_token_url(repo_server) or \
           not re.fullmatch(r'[A-Za-z0-9._~/-]+', repo_repo) or not re.fullmatch(r'[A-Za-z0-9._-]+', repo_name):
            self.log.error("Registration error: repository info is not allowed %s" % (repo))
            return False
        # Get current repo configuration
        repo_files = glob.glob(fwglobals.g.REPO_SOURCE_DIR + "flexiwan*")
        if len(repo_files) != 1:
            self.log.error("Registration error: Folder %s must include a single repository file, found %d" %
                (fwglobals.g.REPO_SOURCE_DIR, len(repo_files)))
            return False
        repo_file = repo_files[0]
        with open(repo_file, 'r') as f:
            repo_config = f.readline().strip()
        # format of repo_config is, get all parameters
        # deb [ arch=amd64 ] https://deb.flexiwan.com/flexiWAN bionic main
        repo_match = re.match(r'^deb[ \t]+\[[ \t]*arch=(.+)[ \t]*\][ \t]+(http.*)/(.+)[ \t]+(.+)[ \t]+(.+)$',
            repo_config)
        if not repo_match:
            self.log.error("Registration error: repository configuration can't be parsed. File=%s, Config=%s" %
                (repo_file, repo_config))
            return False
        (found_arch, found_server, found_repo, found_distro, found_name) = repo_match.group(1,2,3,4,5)
        # Check if not the same as configured
        if (found_server != repo_server or found_repo != repo_repo or found_name != repo_name):
            new_repo_config = "deb [ arch=%s ] %s/%s %s %s\n" % (found_arch, repo_server, repo_repo, found_distro, repo_name)
            with open(repo_file, 'w') as f:
                fwutils.file_write_and_flush(f, new_repo_config)
            self.log.info("Overwriting repository from token, token_repo=%s, prev_repo_config=%s, new_repo_config=%s" %
                (repo, repo_config, new_repo_config))
        return True

    def _decode_token_and_setup_environment(self, token):
        """Decode token and setup environment variables if required.
        The environment setup is needed when the non default flexiManage server is used.
        This could be on test, a dedicated, or a self hosting flexiManage setup.
        After installing the flexiEdge software, it contains the default server and repository.
        The software can be installed as a debian install on Linux, an ISO installation or,
        pre installed by the hardware vendor.
        In this case the server and repository flexiEdge has are different than what should be used.
        The token is generated in flexiManage and installed on the device.
        The token may encode the server and the repository parameters.
        When the token is installed on flexiEdge, we check the server and repository decoded and
        setup the system accordingly.
        We call this function before registration when the token file is first processed

        :returns: `True` if succeeded, `False` otherwise.
        """
        try:
            parsed_token = jwt.decode(token, options={"verify_signature": False})
        except Exception as _e:
            self.log.error(f"invalid token (length={len(token) if token else 0})")
            raise _e

        # If repository defined in token, make sure device works with that repo
        # Repo is sent if device is connected to a flexiManage that doesn't work with
        # the default flexiWAN repository
        repo = parsed_token.get('repo')
        if repo:
            if not self._setup_repository(repo):
                raise AssertionError("failed to setup repository")

        # Setup the flexiManage server to work with
        server = parsed_token.get('server')
        if server:
            if not self._is_allowed_token_url(server):
                raise AssertionError(f"management server {server} from token is not allowed")
            if server != fwglobals.g.cfg.MANAGEMENT_URL:
                self.log.warning(f"management url from token {server} differs from configured {fwglobals.g.cfg.MANAGEMENT_URL}")
            # Use server from token
            fwglobals.g.cfg.MANAGEMENT_URL = server
            self.log.info(f"use management url from token: {server}")

    def is_registered(self):
        """Check if agent is already registered with the flexiManage.

        :returns: `True` if registered, `False` otherwise.
        """
        # Presence of DEVICE_TOKEN_FILE file is enough to deduce successful registration,
        # but to avoid heavy open() and read() calls we cache it into 'self.registered' variable.
        #
        if self.registered:
            return True
        else:
            try:
                with open(fwglobals.g.DEVICE_TOKEN_FILE, 'r') as fin:
                    device_token = fin.readline()
                    if device_token:
                        return True
            except Exception:
                pass
            return False

    def register(self, machine_id=None):
        """Registers device with the flexiManage.
        To do that the Fwagent establishes secure HTTP connection to the manager
        and sends GET request with various data regarding device.
        When user approves device on manager, the Fwagent establishes secure
        WebSocket connection to the manager and starts to listen for flexiManage
        requests.

        :returns: tuple (<registration succeeded>, <received error>)
        """
        def _return(registered=False, received_error=None, device_token=None):
            return (registered, received_error, device_token)


        self.log.info("registering with flexiManage...")

        try:
            with open(fwglobals.g.cfg.TOKEN_FILE, 'r') as f:
                self.token = f.readline().strip()
        except Exception:
            err = "register: failed to load token from %s: %s (%s)" % \
                (fwglobals.g.cfg.TOKEN_FILE, format(sys.exc_info()[1]),  format(sys.exc_info()[0]))
            self.log.error(err)
            return _return(registered=False)

        # Token found, decode token and setup environment parameters from token
        try:
            self._decode_token_and_setup_environment(self.token)
        except Exception as _e:
            self.log.excep(f"register: bad token (check {fwglobals.g.cfg.TOKEN_FILE}): {_e}, ({traceback.format_exc()})")
            return _return(registered=False, received_error='invalid token')  # simulate received 'invalid token' to trigger token polling for modifications

        if fw_os_utils.vpp_does_run():
            self.log.error("register: router is running, it by 'fwagent stop' and retry by 'fwagent start'")
            return _return(registered=False)

        if not machine_id:
            machine_id = fwutils.get_machine_id()
            if not machine_id:
                self.log.error("register: get_machine_id failed, make sure you're running in sudo privileges")
                return _return(registered=False)

        machine_name = socket.gethostname()
        all_ip_list = socket.gethostbyname_ex(machine_name)[2]
        interfaces          = list(fwutils.get_linux_interfaces(cached=False).values())
        (dr_via, dr_dev, _, _, _) = fwutils.get_default_route()
        # get up to 4 IPs
        ip_list = ', '.join(all_ip_list[0:min(4,len(all_ip_list))])
        serial = fwutils.get_machine_serial()
        url = fwglobals.g.cfg.MANAGEMENT_URL  + "/api/connect/register"
        with fwsystem_checker_common.Checker() as checker:
            cpu_info = checker.get_cpu_info()
        linux_version, codename = fwutils.get_linux_distro()

        data = {'token': self.token.rstrip(),
                'agent_version' : self.versions['components']['agent']['version'],
                'router_version' : self.versions['components']['router']['version'],
                'device_version' : self.versions['device'],
                'machine_id' : machine_id,
                'serial' : serial,
                'machine_name': machine_name,
                'ip_list': ip_list,
                'default_route': dr_via,
                'default_dev': dr_dev,
                'interfaces': interfaces,
                'cpuInfo': cpu_info,
                'distro': {'version': linux_version, 'codename': codename},
        }
        self.log.debug("Registering to %s with: %s" % (url, fw_redact.dumps(data)))
        data.update({'interfaces': json.dumps(interfaces)})
        data = uparse.urlencode(data).encode()
        req = ureq.Request(url, data)
        ctx = ssl.create_default_context()
        if fwglobals.g.cfg.BYPASS_CERT:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            resp = ureq.urlopen(req, context=ctx)
            device_token = resp.read().decode()
            # save received token on disk to survive reboots.
            # The token is a secret, so make it readable by root only.
            fd = fw_os_utils.open_private_file(fwglobals.g.DEVICE_TOKEN_FILE, mode=0o600)
            with os.fdopen(fd, 'w') as f:
                fwutils.file_write_and_flush(f, device_token)
            self.log.info("Registration succeeded:")
            self.log.info("  Hostname:  " + machine_name)
            self.log.info("  IP List:   " + ip_list)
            self.log.info("  Device ID: " + machine_id)
            return _return(registered=True, device_token=device_token)

        except uerr.URLError as _e:
            received_error = None
            if hasattr(_e, 'code'):
                server_response = _e.read().decode()
                latestVersion = _e.headers.get('latestVersion','None')
                self.log.error('register: got %s - %s' % (str(_e.code), hsvr.BaseHTTPRequestHandler.responses[_e.code][0]))
                self.log.error('register: Server response: %s' % server_response)
                self.log.error('latestVersion: %s' % (latestVersion))
                try:
                    register_response = json.loads(server_response)
                    if 'error' in register_response:
                        received_error = register_response['error'].lower()
                except Exception:
                    pass
                if _e.code == 403: # version too low, try to upgrade immediately
                    self.log.error('Trying device auto upgrade...')
                    fwglobals.g.inject_request({'message':'upgrade-device-sw','params':{'version':latestVersion}}, f"Device auto upgrade to ({latestVersion})")
                return _return(received_error=received_error)
            elif hasattr(_e, 'reason'):
                self.log.error('register: failed to connect to %s: %s' % (fwglobals.g.cfg.MANAGEMENT_URL, _e.reason))
            return _return(registered=False)

        except Exception:
            self.log.error('register: failed to send request to server %s: %s' % \
                        (fwglobals.g.cfg.MANAGEMENT_URL, format(sys.exc_info()[1])))
            return _return(registered=False)

    def connect(self, machine_id, device_token):
        """Establishes the main WebSocket connection between device and manager,
        on which Fwagent receives manager requests, and enters into the infinite
        event loop on it.

        :param machine_id:   the UUID of the device to be used for connection
        :param device_token: the device token obtained during registration

        :returns: `True` if connection was established and than was closed gracefully,
                  `False` otherwise.
        """
        self.log.info("connecting to flexiManage...")

        try:
            device_token_data = json.loads(device_token)
            url = "wss://%s/%s?token=%s" % (device_token_data['server'], machine_id, device_token_data['deviceToken'])
            headers = {
                "User-Agent": "fwagent/%s" % (self.versions['components']['agent']['version'])
            }
            self.ws.connect(
                        url, headers = headers,
                        check_certificate=(not fwglobals.g.cfg.BYPASS_CERT))
            return True, None

        except Exception as _e:  # see https://pypi.org/project/websocket-client/ for format of '_e'
            received_reject = getattr(_e, 'status_code', None)
            error = "not approved" if received_reject == fwglobals.g.WS_STATUS_NOT_APPROVED else str(_e)
            if not self.start_stop_router_seq:
                self.log.error(f"connect: {error}")

            # Record failure for upgrade process: if failed to connect, upgrade will be reverted
            try:
                with open(fwglobals.g.CONN_FAILURE_FILE, 'w') as f:
                    fwutils.file_write_and_flush(f, f'Failed to connect to flexiManage: {error}')
            except Exception as __e:
                self.log.excep(f"Failed to create connection failure file:  {__e}")
            return False, received_reject

    def connect_to_management(self):
        if not self.connection_thread:
            self.registered           = False
            self.register_error       = None
            self.register_bad_token   = None
            self.register_scheduled   = 0  # in ticks
            self.connected            = False
            self.connect_scheduled    = 0  # in ticks
            self.last_received_time   = 0  # in ticks

            self.log.debug("connect_to_management: initiated")
            self.connection_thread = fwthread.FwThread(target=self.connection_thread_func, name='Management Connection', log=self.log)
            self.connection_thread.start()
        else:
            status = "connected" if self.ws.is_connected() else "in progress"
            self.log.debug(f"connect_to_management: {status}")

    def disconnect_from_management(self):
        if self.connection_thread:
            self.log.debug("disconnect_from_management: stop connection loop")
            self.connection_thread.stop()
            self.connection_thread = None
        if self.ws.is_connected():
            self.log.debug("disconnect_from_management: disconnect")
            self.ws.disconnect()
        self.log.debug("disconnect_from_management: disconnected")

    def _register(self, ticks):
        '''Wrapper for the register() method that decides if the register()
        should be called indeed. This wrapper is called from within FwThread
        function nearly every second (aka tick).
        '''
        if ticks < self.register_scheduled:
            return False

        if self.register_bad_token:   # no sense to register if token is bad
            f = open(fwglobals.g.cfg.TOKEN_FILE, 'r')
            new_token = f.readline()
            f.close()
            if new_token == self.register_bad_token:
                # still same bad token, reschedule next check
                self.register_scheduled = ticks + 10
                return False

        self.registered, received_error, _ = self.register()
        if self.registered:
            self.register_bad_token = None
            return True

        # If registration was rejected due to invalid authentication token,
        # postpone registration until it is modified by user.
        #
        self.register_bad_token = None
        if received_error == 'token not found' or received_error == 'invalid token':
            self.log.debug(f'poll {fwglobals.g.cfg.TOKEN_FILE} for modification')
            with open(fwglobals.g.cfg.TOKEN_FILE, 'r') as f:
                self.register_bad_token = f.readline()
            self.register_scheduled = ticks + 10

        # If we got same registration reject twice - stop connection loop.
        #
        elif received_error:
            if received_error == self.register_error:
                self.log.info("stop registration trials, use 'fwagent start' to resume")
                self.connection_thread.stop()
                self.connection_thread = None
            else:
                self.register_error = received_error

        # Re-schedule registration.
        #
        else:
            retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            self.log.info(f"retry registration in {retry_sec} seconds")
            self.register_scheduled = ticks + retry_sec
        return False

    def _connect(self, ticks):
        '''Wrapper for the connect() method that decides if the connect()
        should be called indeed. This wrapper is called from within FwThread
        function nearly every second (aka tick).
        '''
        if ticks < self.connect_scheduled:
            return False

        if not self.ws.is_idle():
            self.log.debug("_connect: connecting or disconnecting in progress, return")
            return False

        machine_id = fwutils.get_machine_id()
        if machine_id is None:
            self.log.error("failed to retrieve UUID -> stop connection trials (restart agent to resume)")
            self.connection_thread.stop()
            self.connection_thread = None
            return False

        try:
            with open(fwglobals.g.DEVICE_TOKEN_FILE, 'r') as fin:
                device_token = fin.readline()
        except Exception:
            self.log.error(f"failed to retrieve device token ({fwglobals.g.DEVICE_TOKEN_FILE}) -> stop connection trials (restart agent to resume)")
            self.connection_thread.stop()
            self.connection_thread = None
            return False

        self.connected, received_reject = self.connect(machine_id, device_token)
        if not self.connected:
            # Retry shortly on NOT APPROVED reject or if response was not received at all, probably
            # due to some internal error. Otherwise go for long retransmission interval.
            #
            if received_reject == fwglobals.g.WS_STATUS_NOT_APPROVED or not received_reject:
                retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            else:
                retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_LONG_MIN, fwglobals.g.RETRY_INTERVAL_LONG_MAX)
            self.log.info(f"retry connection in {retry_sec} seconds")
            self.connect_scheduled = ticks + retry_sec

        if self.connected or not received_reject:  # if not connected update watchdog on no-response only
            fwglobals.g.watchdog.update_connection_status(connected=self.connected)
        return self.connected

    def receive(self, timeout=0):
        """Implements single read-write iteration on WebSocket connection to flexiManage:
        waits for incoming request, handles it and sends back reply if available.
        The waiting is limited by timeout.
        Note, request handling is asynchronous - the received request is pushed into queue.
        The reply is popped out of queue, so actually  the returned replies present responses
        for the requests received earlier. In addition, multiple replies can be sent,
        as this function reads all available replies from the queue and sends them.

        :param timeout: how long to wait for incoming message in recv() - in seconds.

        :return: True if message was received, False otherwise.
        """
        received = None
        try:
            received = self.ws.recv(timeout=timeout)
            msg = json.loads(received) if received else None

            # Suppress exception and error log prints by WebSocket on VPP start/stop
            # to calm down customers and QA :)
            #
            req = msg['msg']['message'] if msg else None
            if req == 'start-router' or req == 'stop-router':
                self.ws.push_logger(fwglobals.g.logger_devnull)
                self.start_stop_router_seq = msg['seq']

            if req in fwglobals.g.cfg.debug['agent']['requests']['ignored']:
                out_msgs = [{'seq':msg['seq'], 'msg':{'ok':1}}]
                if req == "sync-device":
                    fwutils.reset_device_config_signature()  # prevent flexiManage to retry 'sync-device'
            else:
                out_msgs = fwglobals.g.message_handler.handle_incoming_message(msg)
            # pop the oldest item in the database, if max size exceeded
            if out_msgs and len(fwglobals.g.memdb.fetch('agent/pending_replies', {})) >= fwglobals.g.MAX_PENDING_REPLIES:
                fwglobals.g.memdb.list_pop('agent/pending_replies')
            for msg in out_msgs:
                if msg['seq'] == self.start_stop_router_seq:
                    self.ws.pop_logger()
                    self.start_stop_router_seq = None
                # Save outgoing messages to re-send them if connection would be broken
                fwglobals.g.memdb.list_insert('agent/pending_replies', msg, at_head=False)
                sent = self.package_and_send(msg)
                if not sent:
                    self.log.info(f"probably not connected -> queue reply {msg['seq']}")
        except Exception as _e:
            if not self.start_stop_router_seq:
                self.log.warning(f"failed to receive/handle/send message: {str(_e)}")
        finally:
            if self.start_stop_router_seq:
                self.start_stop_router_seq = None
                self.ws.pop_logger()
        return received

    def package_and_send(self, msg):
        """
        In some cases on slow connections, sending a big data chunk causes
        TCP stuck and break the SSL connection.
        To overcome this issue, check the size of the message. If it's too big,
        divide it into smaller chunks. from release 6.4.X flexiManage knows to
        address multiple chunks and combine the messages together.
        All responses are now also compressed and b64 encoded to reduce the size
        and network bandwidth.

        :param msg:      message object to send, including seq and msg

        """
        if isinstance(msg, str):
            # Replying old structure message (could be when queueing reply on previous release)
            return self.ws.send(msg)

        # New structure message
        SPLIT_SIZE = 8192
        seq = msg['seq']
        msg_str = json.dumps(msg['msg'], cls=fwutils.FwJsonEncoder)
        data = fwutils.compress_encode_string(msg_str)
        data_len = len(data)
        if (data_len > SPLIT_SIZE): # Message too big, send in chunks
            # For the last chunk we divide data_len by SPLIT_SIZE
            # A special case is where it's exactly divided where we need to decrease 1
            # For example, if data_len is exactly 8192, the division is 1
            # so we need to reduce 1 because it's only one chunk (last_chunk = 0)
            # Here, data_len > SPLIT_SIZE so last chunk should be > 0
            last_chunk = data_len // SPLIT_SIZE -(1 if data_len % SPLIT_SIZE == 0 else 0)
            curr_chunk = 0
            for chunk in (data[0+i:SPLIT_SIZE+i] for i in range(0, data_len, SPLIT_SIZE)):
                chunk_msg = (f'{{'
                             f'"seq": "{seq}", '
                             f'"msg": "{chunk}", '
                             f'"chunk": {curr_chunk}, '
                             f'"lastChunk": {last_chunk}, '
                             f'"compressed": 1'
                             f'}}')
                sent = self.ws.send(chunk_msg)
                if not sent:
                    break # if one chunk not sent, break, flexiManage will timeout this message
                time.sleep(fwglobals.g.cfg.MESSAGE_TRANSMISSION_DELAY_BETWEEN_CHUNKS)
                curr_chunk += 1
        else: # Small size message, send as is
            full_msg = (f'{{'
                        f'"seq": "{seq}", '
                        f'"msg": "{data}", '
                        f'"compressed": 1'
                        f'}}')
            sent = self.ws.send(full_msg)
        return sent

    def connection_thread_func(self, ticks):
        """Implementation of the main connection loop.
        The main connection loop keeps Fwagent registered and connected to flexiManage.
        If connected, it reads flexiManage request from the connection and sends
        back available responses.
        Note this function is called by FwThread framework nearly every second.
        """
        if not self.is_registered():
            if not self._register(ticks):
                return

        if not self.ws.is_connected():
            if not self._connect(ticks):
                return
            self.last_received_time = 0

        received = self.receive()  # run single read-write iteration

        # If no request was received in some period, drop connection to cause reconnect
        #
        self.last_received_time = 0 if received else self.last_received_time + 1
        if self.last_received_time > fwglobals.g.WS_TIMEOUT:
            self.log.info(f"no request in {fwglobals.g.WS_TIMEOUT} seconds - reconnect")
            self.ws.disconnect()

    def reconnect(self):
        """Closes and reestablishes the main WebSocket connection between
        device and manager, on which Fwagent receives manager requests.
        When WAN address or default route are changed, the connection might
        loose connectivity, while relying on TCP/WebSocket keep-alive mechanism
        to detect that. That might take up to few minutes! As we have full
        control of device IPs and routes, we can short the connection down period
        significantly by enforcing connection re-establishment.
        This function closes the current connection and opens the new one.
        """

        # Avoid reconnect by route_thread_func() due to change in default route.
        # That should avoid unnecessary reconnection, when default route is changed
        # due to 'start-router'/'stop-router' execution, as in these cases
        # the agent is reconnected explicitly. The explicit reconnection is done
        # for various reasons. On start we want to have connection as soon as
        # interfaces are configured and before any heavy configurations, like
        # applications or policies. On stop (and on start) the default route might
        # look exactly same as before stop/start, if 'set-name' option is used
        # in netplan to have persistent interface name.
        #
        fwglobals.g.routes.default_route = None

        if self.ws == None:
            self.log.info("flexiManage is not connected, ignore reconnection request")
        elif self.reconnecting:
            self.log.info("reconnection to flexiManage was initiated already")
        else:
            self.log.info("initiate reconnection to flexiManage")
            self.reconnecting = True
            self.ws.disconnect()
            # The new connection will be opened by the FwagentDaemon object from
            # within the connection loop, when the current connection
            # will be closed gracefully.


    def _on_close(self):
        """Websocket connection close handler

        :returns: None.
        """
        self.log.info("connection to flexiManage was closed")

    def _on_open(self):
        """Websocket connection open handler

        :returns: None.
        """
        self.log.info("connected to flexiManage")

        self.reconnecting = False

        # Update connection status file used by fwupgrade.sh.
        # We use 'subprocess.check_call()' to get an exception if writing into file fails.
        # The file update is vital for the upgrade process.
        #
        subprocess.check_call(f'echo "success" > {fwglobals.g.CONN_FAILURE_FILE}', shell=True)

        # Send pending message replies to the flexiManage upon connection reopen.
        # These are replies to messages that might have cause the connection
        # to the flexiManage to disconnect, and thus have to be sent on the new connection.
        #
        msg = fwglobals.g.memdb.list_pop('agent/pending_replies')
        while msg:
            log_msg = msg if isinstance(msg, str) else msg['seq']
            self.log.debug(f"_on_open: sending reply: {log_msg}")
            sent = self.package_and_send(msg)
            if not sent:
                # Print error but don't send again to prevent loop of errored message
                self.log.debug(f"_on_open: failed to send pending reply: {log_msg}")
                break
            msg = fwglobals.g.memdb.list_pop('agent/pending_replies')

        if not fw_os_utils.vpp_does_run():
            self.log.info("connect: router is not running, start it in flexiManage")

    def disconnect(self):
        """Shutdowns the WebSocket connection.

        :returns: None.
        """
        if self.ws:
            self.ws.disconnect()

    def inject_requests(self, filename=None, ignore_errors=False, json_requests=None):
        """Injects requests loaded from within 'file' JSON file,
        thus simulating receiving requests over network from the flexiManage.
        This function is used for Unit Testing.

        :param filename:      name of the JSON file, were from to load requests.

        :param ignore_errors: if False, failure to inject some of the loaded
                              requests will cause this function to return, so
                              rest of loaded requests will be not executed.
        :param json_requests: EITHER
                                string with one request or with list of requests
                                formatted as json. E.g.
                                    '[ {"message": "get-device-stats"}, {"message": "get-device-info"} ]'
                              OR
                                single request as a dict
                              String format is exactly same as a content of 'filename'.
                              The 'filename' is ignored, if 'json_requests' is provided.
        :returns: reply if one request only was injected. 'None' otherwise.
                  Note, to get reply for multiple requests you can inject aggregated request.
        """
        def _inject_single_request(request, seq=None, ignore_errors=False):
                if not seq:
                    # Create C-like static variable that counts invocations of this method
                    #
                    if not hasattr(_inject_single_request, 'seq'):
                        _inject_single_request.seq = 0  # Initialize counter once
                    else:
                        _inject_single_request.seq += 1
                    seq = _inject_single_request.seq

                incoming_message = {
                    'seq':          seq,
                    'msg':          request
                }
                request.update({   # bypass queue to have response immediately
                    'processing': { 'synchronous' : True }
                })
                outgoing_messages = fwglobals.g.message_handler.handle_incoming_message(incoming_message)
                if not outgoing_messages and ignore_errors == False:
                    raise Exception(f'failed to inject request #{seq} in {filename}: got no reply')
                reply = outgoing_messages[0]['msg']
                if reply['ok'] == 0 and ignore_errors == False:
                    raise Exception(f"failed to inject request #{seq} in {filename}: {reply['message']}")
                return reply


        self.log.debug(f"inject_requests({filename}, ignore_errors={ignore_errors})")

        if not json_requests:
            with open(filename, 'r') as f:  json_requests = f.read()
        if isinstance(json_requests, str):
            requests = json.loads(json_requests)
        elif isinstance(json_requests, dict):
            requests = json_requests

        if type(requests) is list:   # Take care of file with list of requests
            for (idx, req) in enumerate(requests):
                _inject_single_request(req, seq=(idx+1), ignore_errors=ignore_errors)
            return None
        else:   # Take care of file with single request
            reply = _inject_single_request(requests)
            return reply

def simulate(count, reconnect, delete):
    """Handles 'fwagent simulate' command.
    The load simulator is imported on demand only, as it is used for testing only.
    """
    import loadsimulator
    return loadsimulator.simulate(count=count, reconnect=reconnect, delete=delete)

def version():
    """Handles 'fwagent version' command.

    :returns: None.
    """
    with open(fwglobals.g.VERSIONS_FILE, 'r') as stream:
        versions = yaml.load(stream, Loader=yaml.BaseLoader)

        # Find the longest name of component
        width = 0
        for component in versions['components']:
            if len(component) > width:
                width = len(component)
        delimiter = '-' * (width + 10)

        print(delimiter)
        print('Device %s' % versions['device'])
        print(delimiter)
        for component in sorted(list(versions['components'].keys())):
            print('%s %s' % (component.ljust(width), versions['components'][component]['version']))
        print(delimiter)

def dump(filename, path, clean_log, full):
    fwutils.fwdump(filename=filename, path=path, clean_log=clean_log, normal_dump=(not full), full_dump=full)

def reset(soft=False, quiet=False, pppoe=False):
    """Handles 'fwagent reset' command.
    Resets device to the initial state. Once reset, the device MUST go through
    the registration procedure.

    :param soft:  Soft reset: resets router configuration only.
                  No re-registration is needed.
    :param quiet: Quiet reset: resets router configuration without confirmation
                  of device deletion in management.
    :param pppoe: PPPoE reset: resets PPPoE configuration.

    :returns: None.
    """

    # prevent reset configuration when vpp is run
    if fw_os_utils.vpp_does_run() and soft:
        print("Router must be stopped in order to reset the configuration")
        return

    if soft:
        fwutils.reset_device_config(pppoe)
        return

    with fwikev2.FwIKEv2() as ike:
        ike.reset()

    reset_device = True
    if not quiet:
        CSTART = "\x1b[0;30;43m"
        CEND = "\x1b[0m"
        choice = input(CSTART + "Device must be deleted in flexiManage before resetting the agent. " +
                        "Already deleted in flexiManage y/n [n]" + CEND)
        if choice != 'y' and choice != 'Y':
            reset_device = False

    if not reset_device:
        return

    if not pppoe and fwpppoe.is_pppoe_configured():
        fwglobals.log.info("Note: this command doesn't clear pppoe configuration, use 'fwagent reset -p' to clear it")


    daemon_was_alive = daemon_is_alive()
    if daemon_was_alive:
        stop(stop_router=True, stop_applications=True)  # Stop daemon main loop
        daemon_rpc_safe('reset_device', pppoe=pppoe)
        pppoe = False  # no need to reset it again later, if it was reset by reset_device()
    else:
        if fw_os_utils.vpp_does_run():
            print("stopping the router...")
            fwutils.stop_vpp()

    with FWAPPLICATIONS_API() as applications_api:
        applications_api.reset()

    fwutils.reset_device_config(pppoe, recovery_netplan=True)

    if os.path.exists(fwglobals.g.DEVICE_TOKEN_FILE):
        os.remove(fwglobals.g.DEVICE_TOKEN_FILE)

    fwlte.disconnect_all()

    fwutils.netplan_apply("reset")

    if daemon_was_alive:
        start(start_router=False, start_applications=True)  # Start daemon main loop

    fwglobals.log.info("reset operation done")


def stop(stop_router, stop_applications):
    """Handles 'fwagent stop' command.
    Stops the infinite connection loop run by Fwagent in daemon mode.
    See documentation on FwagentDaemon class.

    :param stop_router:          Stop router, thus disabling packet routing.
    :param stop_applications:    Uninstall all applications.

    :returns: None.
    """
    try:
        daemon_rpc('stop_agent', stop_router=stop_router, stop_applications=stop_applications)
    except:
        # If failed to stop, kill vpp from shell and get interfaces back to Linux
        if stop_router:
            fwglobals.log.excep("failed to stop vpp gracefully, kill it")
            fwutils.stop_vpp()

def start(start_router, start_applications):
    """Handles 'fwagent start' command.
    Starts the infinite connection loop run by Fwagent in daemon mode.
    See documentation on FwagentDaemon class.

    :param start_router:  Start router, while applying router configuration.
    :param start_applications:  Start application watchdog thread to keep applications running.

    :returns: None.
    """
    daemon_rpc_safe('start_agent', start_router=start_router, start_applications=start_applications) # if daemon runs, start connection loop and router if required

def show(agent, configuration, database, status, networks, watchdog):
    """Handles 'fwagent show' command.
    This commands prints various information about device and it's components,
    like router configuration, software version, etc.
    For full list of available options to show use 'fwagent --help'.

    :param agent:          Agent information.
    :param configuration:  Configuration information.
    :param database:       Databases information.
    :param status:         Status information.
    :param networks:       Device networks information.
    :param watchdog:       Device watchdogs information.

    :returns: None.
    """

    if configuration:
        if configuration == 'all':
            fwutils.print_router_config()
            fwutils.print_system_config()
        elif configuration == 'router':
            fwutils.print_router_config()
        elif configuration == 'router-pending':
            fwutils.print_router_pending_config()
        elif configuration == 'system':
            fwutils.print_system_config()
        elif configuration == 'multilink-policy':
            fwutils.print_router_config(basic=False, multilink=True)
        elif configuration == 'signature':
            fwutils.print_device_config_signature()

    if networks:
        networks_type = None if networks == 'all' else networks
        out = daemon_rpc_safe('show', what='networks', type=networks_type)
        if out:
            print(out)

    if agent:
        out = daemon_rpc_safe('show', what=agent)
        if out:
            print(out)

    if database:
        if database == 'router':
            fwutils.print_router_config(full=True)
        elif database == 'router-pending':
            fwutils.print_router_pending_config(full=True)
        elif database == 'system':
            fwutils.print_system_config(full=True)
        elif database == 'general':
            fwutils.print_general_database()
        elif database == 'applications':
            fwutils.print_applications_db(full=True)
        elif database == 'frr':
            with FwFrr(fwglobals.g.FRR_DB_FILE, fill_if_empty=False) as frr_db:
                print(frr_db.dumps())
        elif database == 'multilink':
            with fwmultilink.FwMultilink(fwglobals.g.MULTILINK_DB_FILE, fill_if_empty=False) as multilink_db:
                print(multilink_db.dumps())
        elif database == 'firewall':
            with FwFirewall() as firewall:
                print(firewall.dumps())
        elif database == 'qos':
            print(fwqos.qos_db_dumps())
        elif database == 'jobs':
            fwutils.print_jobs()

    if status:
        if status == 'daemon':
            try:
                daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
                daemon.ping()   # Check if daemon runs
                fwglobals.log.info("running")
            except Pyro4.errors.CommunicationError:
                fwglobals.log.info("not running")
            except FileNotFoundError:
                fwglobals.log.info("initializing")
            except RuntimeError:
                fwglobals.log.info("starting")

        elif status == 'router':
            fwglobals.log.info('Router state: %s (%s)' % (fwutils.get_router_status()[0], fwutils.get_router_status()[1]))

    if watchdog:
        if watchdog == 'connection':
            out = daemon_rpc_safe('show', what='recovery', type=watchdog)
            if out:
                print(out)

# Methods of FwagentDaemon that might be invoked by RPC (see rpc_handler()).
#
FWAGENT_DAEMON_RPC_METHODS = ('ping', 'show', 'start_agent', 'stop_agent', 'reset_device', 'api')

# Agent modules which functions might be invoked by the 'api' RPC with 'api_module'
# argument. No in-tree caller uses this option, so the list is empty.
# Add module names here explicitly, if needed. Never add modules that provide
# generic execution primitives, like fwutils or fw_os_utils.
#
FWAGENT_DAEMON_RPC_API_MODULES = ()

class FwagentRpcDaemon(Pyro4.Daemon):
    """Pyro4 daemon that serves RPC-s on unix socket and accepts connections
    from root processes only. The socket itself resides in a root-only directory
    and has 0600 permissions, so the SO_PEERCRED check is defense in depth.
    """
    def validateHandshake(self, conn, data):
        try:
            creds = conn.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', creds)
        except Exception as e:
            raise Pyro4.errors.SecurityError(f"failed to get peer credentials: {e}")
        if uid != 0 and uid != os.geteuid():
            raise Pyro4.errors.SecurityError(f"RPC from uid {uid} is not allowed")
        return super().validateHandshake(conn, data)

@Pyro4.expose
class FwagentDaemon(FwObject):
    """This class implements abstraction of Fwagent that runs in daemon mode.
    When the Fwagent runs as a daemon, someone has to create it and to invoke
    registration, connection and other Fwagent functionality, while keeping
    the Fwagent connected to flexiManage. These tasks are performed
    by the FwagentDaemon object.
    So the FwagentDaemon is responsible for:
        1. Creation and configuration the Fwagent object
        2. Running infinite loop of the Fwagent registration & WebSocket
           connection retrials, named the 'main daemon loop'.
        3. Listening for CLI commands that effect on the main daemon loop,
           like 'fwagent start', 'fwagent stop', etc.
        4. Listening for CLI commands that are designated for the Fwagent object
           itself and proxying them to it.

    The FwagentDaemon object is created by the 'fwagent daemon' command.
    """
    def __init__(self):
        """Constructor method.

        """
        FwObject.__init__(self)

        self.agent                  = None
        self.thread_rpc_loop        = None
        self.event_exit             = None

        self.agent_started          = False

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)

    def _signal_handler(self, signum, frame):
        sig_name = fwglobals.g.signal_names[signum]
        self.log.info(f"got {sig_name}")
        if self.event_exit:
            self.event_exit.set()
        else:
            self.log.info(f"agent initialization was not finished, exit on {sig_name}")
            # os._exit() terminates the process with no regards to state of daemon
            # and other threads. We need it to enforce FwagentDaemon termination
            # when agent initialization was not finished, so its state is not defined yet.
            #
            os._exit(os.EX_OK)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        return

    def _check_system(self):
        """Check system requirements.

        :returns: None.
        """
        root = os.path.dirname(os.path.realpath(__file__))
        checker = os.path.join(root, 'tools' , 'system_checker' , 'fwsystem_checker.py')
        try:
            # Use "subprocess.check_output" to suppress prints onto screen :)
            subprocess.check_output(['python3' , checker , '--check_only'])
            return True
        except subprocess.CalledProcessError as err:
            self.log.excep( "+=====================================================")
            self.log.excep(f"| System checker failed ({err.returncode})            ")
            self.log.excep( "| To check and configure system run 'fwsystem_checker'")
            self.log.excep( "+=====================================================")
            return False

    def ping(self):
        if not self.agent:
            self.log.debug("ping: there is no agent")
            raise FileNotFoundError()  # We can't use custom exception with proper name, as Pyro4 will not propagate it due to security reasons
        elif not self.agent_started:
            self.log.debug("ping: agent is not started yet")
            raise RuntimeError()   # We can't use custom exception with proper name, as Pyro4 will not propagate it due to security reasons
        else:
            self.log.debug("ping: alive")

    def rpc_handler(self, func, **kwargs):
        '''This wrapper is needed to provide central point for all kinds of validity check
        on called functions. This is needed to avoid unfriendly exception prints.
        So just add checks here when you see exceptions on invoking daemon/agent functions.
        '''
        # The daemon MUST have agent. If agent is in the middle of creation/initialization,
        # disable pretty all API-s excepting the not hurting, like "show".
        #
        if not isinstance(func, str) or func.startswith('_') or func not in FWAGENT_DAEMON_RPC_METHODS:
            raise Exception(f"RPC '{func}' is not allowed")
        if not (fwglobals.g.agent_initialized or func in ['show', 'ping']):
            raise Exception("initializing")
        return getattr(self, func)(**kwargs)

    def start_agent(self, start_router=False, start_applications=False):
        log_prefix = f"start_agent(start_router={start_router},start_applications={start_applications})"
        self.log.debug(f"{log_prefix}: starting")

        fwglobals.g.load_configuration_from_file()      # reload configuration on every start

        if not self.agent:   # ATM we use start/stop as connect/disconnect, so no need to recreate
            self.agent = fwglobals.g.create_agent()

        # Ensure system compatibility with our soft.
        # Do this after initialize_agent(), so we could use router_api.state_is_started().
        # If router was started, it is too late to check the compatibility :)
        #
        if not fwglobals.g.router_api.state_is_started():
            self._check_system()

        if start_router:
            try:
                fwglobals.g.router_api.start_router()
                self.log.debug("vpp started")
            except Exception as _e:
                self.log.excep("failed to start vpp: " + str(_e))
                return

        if start_applications:
            fwglobals.g.applications_api.start_applications()

        if not fwglobals.g.cfg.debug['daemon']['standalone']:
            self.agent.connect_to_management()

        self.log.debug(f"{log_prefix}: started")
        self.agent_started = True



    def stop_agent(self, stop_router=False, stop_applications=False, destroy_agent=False):
        log_prefix = f"stop_agent(stop_router={stop_router},stop_applications={stop_applications})"
        if not self.agent:
            self.log.debug(f"{log_prefix}: no agent to stop")
            return

        self.agent_started = False

        self.log.debug(f"{log_prefix}: stopping")

        self.agent.disconnect_from_management()  # prevent incoming requests
        if destroy_agent:
            self.agent = None                    # prevent RPC-s, see rpc_handler()

        if stop_router:
            try:
                fwglobals.g.inject_request({'message':'stop-router'}, "Stop agent")
                self.log.debug("router stopped")
            except Exception as _e:
                self.log.excep("failed to stop router: " + str(_e))
        elif fwglobals.g.router_api.state_is_started():
            self.log.debug("vpp alive, use 'fwagent stop' to stop it")

        if stop_applications:
            fwglobals.g.applications_api.stop_applications()
        else:
            self.log.debug("applications are alive, use 'fwagent stop' to stop it")

        # ATM we use start/stop as connect/disconnect, so destroy only if asked explicitly
        if destroy_agent:
            fwglobals.g.destroy_agent()

        self.log.debug(f"{log_prefix}: stopped")


    def reset_device(self, pppoe=True):
        '''Implementation of 'fwagent reset' command. Cleans databases, caches, etc.
        of running agent daemon.
        '''
        self.log.debug(f"reset_device: pppoe={pppoe}")
        if pppoe:
            fwglobals.g.pppoe.clean()
        self.log.debug(f"reset_device: done")


    def show(self, what=None, **args):
        if what == 'version':
            return fwutils.get_device_versions(fwglobals.g.VERSIONS_FILE)['components']['agent']['version']
        if what == 'cache':
            return json.dumps(fwglobals.g.cache.db, indent=2, sort_keys=True, cls=fwutils.FwJsonEncoder)
        if what == 'threads':
            threads_summary = {}
            threads_verbose = {}
            for thd in threading.enumerate():
                frame = traceback.format_stack(sys._current_frames()[thd.ident])
                threads_verbose.update({thd.name: frame})
                threads_summary.update({thd.name: thd.ident})
            threads_summary_str = json.dumps(threads_summary, indent=2, sort_keys=True)
            threads_verbose_str = json.dumps(threads_verbose, indent=2, sort_keys=True)
            return threads_summary_str + threads_verbose_str
        if what == 'networks':
            return fwutils.get_device_networks_json(**args)
        if what == 'recovery':
            return fwglobals.g.watchdog.get_connection_recovery_state()


    def api(self, api_name, api_module=None, api_object=None, **api_args):
        """Wrapper for Fwagent methods
        """
        fwglobals.log.trace(f'{api_name}({api_args if api_args else ""}): enter')

        if not isinstance(api_name, str) or api_name.startswith('_'):
            fwglobals.log.error(f'api({api_name}): private or invalid function name is not allowed')
            return
        if api_module and api_module not in FWAGENT_DAEMON_RPC_API_MODULES:
            fwglobals.log.error(f'api({api_name}, {api_module}): module is not allowed')
            return

        if api_object:
            api_func = fwglobals.g.get_object_func(api_object, api_name)
        else:
            module = None
            if not api_module:
                if self.agent:
                    module = self.agent
            else:
                current_dir = os.path.dirname(os.path.realpath(__file__))
                module = fw_os_utils.load_python_module(current_dir, api_module)
            if not module:
                fwglobals.log.error(f'api({api_name}, {api_module}, {api_args if api_args else ""}: No module found)')
                return
            api_func = getattr(module, api_name)

        if not api_func:
            fwglobals.log.error(f'api({api_name}, {api_module}, {api_object}, {api_args if api_args else ""}: Function not found)')
            return

        if api_args:
            func = lambda: api_func(**api_args)
        else:
            func = lambda: api_func()

        ret, ret_str = None, None
        try:
            ret = func()
            ret_str = json.dumps(ret, indent=2, sort_keys=True)
        finally:
            fwglobals.log.trace(f'{api_name}({api_args if api_args else ""}): leave: ret={ret_str}')
        return ret

    def start_rpc_service(self):
        self.log.debug(f"RPC service: start to listen for RPC-s on {fwglobals.g.FWAGENT_DAEMON_URI}")

        if self.thread_rpc_loop:
            self.log.debug("RPC service: already started")
            return

        # The RPC is served on unix socket in root-only directory.
        # Ensure the socket is not in use by other running daemon and remove
        # stale socket file if exists, as Pyro4 fails to bind to existing file.
        #
        sock_path = fwglobals.g.FWAGENT_DAEMON_SOCKET
        fw_os_utils.ensure_private_dir(os.path.dirname(sock_path), 0o700)
        if os.path.lexists(sock_path):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(2)
                probe.connect(sock_path)
                in_use = True
            except OSError:
                in_use = False
            finally:
                probe.close()
            if in_use:
                err_str = f"socket {sock_path} is in use, try other socket (fwagent_conf.yaml:daemon_socket)"
                fwglobals.log.error(err_str)
                raise Exception(err_str)
            os.unlink(sock_path)

        old_umask = os.umask(0o077)   # ensure socket is created with 0600 permissions
        try:
            rpc_daemon = FwagentRpcDaemon(unixsocket=sock_path)
        finally:
            os.umask(old_umask)
        os.chmod(sock_path, 0o600)

        self.thread_rpc_loop = threading.Thread(
                                target=lambda: Pyro4.Daemon.serveSimple(
                                        {self: fwglobals.g.FWAGENT_DAEMON_NAME},
                                        daemon=rpc_daemon,
                                        ns=False,
                                        verbose=False),
                                name='FwagentDaemon RPC Thread',
                                daemon=True)
        self.thread_rpc_loop.start()
        self.log.debug("RPC service: started")

    def stop_rpc_service(self):
        # We have no real way to break the Pyro4.Daemon.serveSimple() loop.
        # So, we just run Pyro4.Daemon.serveSimple() as a daemon thread.
        # That causes the agent to exit, when all non-daemon threads are terminated.
        if self.thread_rpc_loop:
            self.log.debug("RPC service: stopping ...")
            self.thread_rpc_loop = None


def daemon(debug_conf_filename=None, agent_conf_filename=None):
    """Handles 'fwagent daemon' command.
    This command runs Fwagent in daemon mode. It creates the wrapping
    FwagentDaemon object that manages the instance of the Fwagent class and
    keeps it registered and connected to flexiManage.
    For more info See documentation on FwagentDaemon class.

    :param debug_conf_filename: if False the register-and-connect loop will not be started.
    :param agent_conf_filename: Path to agent configuration file to override default file.

    :returns: None.
    """
    fwglobals.log.set_target(to_syslog=True, to_terminal=False)
    fwglobals.log.info("starting in daemon mode")

    if agent_conf_filename:
        fwglobals.g.load_agent_configuration_from_file(agent_conf_filename)

    if debug_conf_filename:
        fwglobals.g.load_debug_configuration_from_file(debug_conf_filename)

    with FwagentDaemon() as agent_daemon:
        agent_daemon.start_rpc_service()
        try:
            agent_daemon.start_agent()

            fwglobals.g.watchdog.start()

            # Initialize 'event_exit' after start_agent()! It is needed to handle properly
            # the Ctrl-C during agent start! See FwagentDaemon._signal_handler().
            #
            agent_daemon.event_exit = threading.Event()
            agent_daemon.event_exit.wait()
            agent_daemon.event_exit.clear()

            fwglobals.g.watchdog.stop()

            agent_daemon.stop_agent(destroy_agent=True)

        except Exception as _e:
            fwglobals.log.excep(f"{_e}: {traceback.format_exc()}")
            # The RPC service is implemented by daemon thread, so if any of our
            # threads are stuck for some reason, it will not exit, holding the FwagentDaemon
            # on the air. So, to be on safe side enforce exit.
            os._exit(os.EX_SOFTWARE)
        agent_daemon.stop_rpc_service()

def daemon_rpc_safe(func, **kwargs):
    return daemon_rpc(func, ignore_exception=True, **kwargs)

def daemon_rpc(func, ignore_exception=False, **kwargs):
    """Wrapper for methods of the FwagentDaemon object that runs on background
    as a daemon. It is used to fullfil CLI commands that can be designated
    either to the FwagentDaemon object itself or to the Fwagent object managed
    by the FwagentDaemon.

    :param func:             Name of FwagentDaemon method to be called.
    :param ignore_exception: If True, the function consumes exception and returns None.
    :param kwargs:           Method parameters.

    :returns: None.
    """
    arguments = json.dumps(kwargs, cls=fwutils.FwJsonEncoder)
    fwglobals.log.debug(f"invoke remote FwagentDaemon::{func}({arguments})", to_terminal=False)

    agent_daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)

    # Firstly try to bind to the running daemon.
    # We do this explicitly to control timeout of connecting.
    try:
        agent_daemon._pyroTimeout = 5  # seconds - avoid stuck on connecting proxy to daemon
        agent_daemon._pyroBind()
    except Exception as _e:
        fwglobals.log.debug(f"FwagentDaemon::{func}({arguments}) failed: {_e}")
        if ignore_exception:
            return None
        raise _e

    # Now invoke the remote procedure
    try:
        agent_daemon._pyroTimeout = 600  # seconds - avoid stuck in remote instance
        return agent_daemon.rpc_handler(func, **kwargs)
    except Pyro4.errors.CommunicationError as _e:
        fwglobals.log.debug(f"FwagentDaemon::{func}({arguments}) failed: {_e}")
        if ignore_exception:
            return None
        raise Exception("daemon does not respond") from _e
    except Exception as _e:
        if ignore_exception:
            exception_str = str(_e)
            fwglobals.log.debug(f"FwagentDaemon::{func}({arguments}) failed: {exception_str}")
            if "not initialized" not in exception_str:
                # Don't print traceback for RPC-s called during agent initialization.
                # Note, we can't use custom exception to avoid ana;lysing exception string,
                # as Pyro4 don't deserializes objects back into instances due to security reasons.
                #
                bt = Pyro4.util.getPyroTraceback()
                fwglobals.log.debug(f"FwagentDaemon::{func}({arguments}) failed: {_e}: {bt}")
            return None
        raise _e

def daemon_is_alive():
    try:
        daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
        daemon._pyroTimeout = 5  # seconds - avoid stuck
        daemon.ping()   # Check if daemon runs
        return True
    except (Pyro4.errors.CommunicationError, FileNotFoundError, RuntimeError):
        return False
    except Exception as e:
        raise e

def cli(clean_request_db=True, api=None, script_fname=None, template_fname=None,
        ignore_errors=False, fallback_to_local_agent=False, quiet=False):
    """Handles 'fwagent cli' command.
    This command is not used in production. It assists unit testing.
    The 'fwagent cli' reads function names and their arguments from prompt and
    executes them on agent that runs in background. If no agent runs in
    background, the command creates new instance of it. When done, this instance
    is destroyed.
        The agent API to be invoked can be provided in one line with command,
    e.g. 'fwagent cli stop()'. In this case the command will not run prompt loop,
    but will execute this API and will exit immediately.
        To stop the read-n-execute loop just ^C it.

    :param clean_request_db:    Clean request database before return.
                                Effectively this flag resets the router configuration.
    :param api:                 The fwagent function to be executed in list format,
                                where the first element is api name, the rest
                                elements are api arguments.
                                e.g. [ 'inject_requests', 'requests.json' ].
                                If provided, no prompt loop will be run.
    :param script_fname:        Shortcut for --api==inject_requests(<script_fname>)
                                command. Is kept for backward compatibility.
    :param template_fname:      Path to template file that includes variables to replace in the cli request.
    :param fallback_to_local_agent: if agent daemon does not run, create local instance of agent.
                                The local instance is terminated on CLI return.
                                !!! THIS FEATURE IS FOR DEVELOPERS ONLY !!!
                                It makes it easy to debug agent when invoking from regression tests,
                                and it enables to use local sources and not /usr/share/flexiwan.
    :returns: None.
    """
    if quiet:
        fwglobals.log.set_target(to_terminal=False)

    fwglobals.log.info("started in cli mode (clean_request_db=%s, api=%s, ignore_errors=%s)" % \
                        (str(clean_request_db), str(api), ignore_errors))

    # Preserve historical 'fwagent cli -f' option, as it involve less typing :)
    # Generate the 'api' value out of '-f/--script_file' value.
    if script_fname:
        # Convert relative path into absolute, as daemon fwagent might have
        # working directory other than the typed 'fwagent cli -f' command.
        script_fname = os.path.abspath(script_fname)
        api = ['inject_requests' , 'filename=%s' % script_fname ]
        if ignore_errors:
            api.append('ignore_errors=True')

        if template_fname:
            requests = fwutils.replace_file_variables(template_fname, script_fname)
            api.append('json_requests=%s' % json.dumps(requests, sort_keys=True))
            fwglobals.log.debug(
                "cli: generate 'api' out of 'script_fname' and 'template_fname': " + str(api))
        else:
            fwglobals.log.debug(
                "cli: generate 'api' out of 'script_fname': " + str(api))

    import fwagent_cli
    with fwagent_cli.FwagentCli(fallback_to_local_agent=fallback_to_local_agent) as cli:
        if api:
            print(api)
            ret = cli.execute(api)

            # We return dictionary with serialized return value of the invoked API,
            # so cli output can be parsed by invoker to extract the returned object.
            #
            if ret['succeeded']:
                if ret['return-value']:
                    ret_val = json.dumps(ret['return-value'])
                else:
                    ret_val = json.dumps({'ok': 1})
            else:
                ret_val = json.dumps({'ok': 0, 'error': ret['error']})
            stdout_ret_val = 'return-value-start ' + ret_val + ' return-value-end'
            fwglobals.log.info(stdout_ret_val)
            print(stdout_ret_val)
        else:
            cli.run_loop()
    if clean_request_db:
        fwglobals.g.router_cfg.clean()
        fwutils.reset_device_config_signature("empty_cfg")
        with fwrouter_cfg.FwRouterCfg(fwglobals.g.ROUTER_PENDING_CFG_FILE) as router_pending_cfg:
            router_pending_cfg.clean()

def handle_cli_command(args):
    """Handles 'fwagent' CLI command.
    This function is responsible for taking CLI arguments, analyzing them and
    mapping them to a CLI module and function that will be called to continue the process.

    For example, for the following command:
    "fwagent configure router interfaces create -addr 8.8.8.8/32 --type lan --host_if_name test"
    the "args" looks as follows:
    {
        command: 'configure',
        configure: 'router',
        router: 'interfaces',
        interfaces: 'create',
        params.addr: '8.8.8.8/32',
        params.host_if_name: 'test',
        params.type: 'lan',
    }

    The derived CLI module name will be: "fwcli_configure_router"
    The derived function name will be: "interfaces_create"

    Comments inside the function are based on the example above.
    """
    cli_module_name = f'fwcli'
    cli_func_name        = ''
    cli_params      = {}

    def _build_cli_params():
        for key in args.__dict__:
            if key.startswith('params.'):
                cli_params[key.split('.')[-1]] = args.__dict__[key]

    def _build_cli_func(step):
        nonlocal cli_func_name

        cli_func_name += f'_{step}' # -> _interfaces
        # start building cli params immediately whenever the step argument
        # is already a function name, for example, with this command:
        # fwagent configure router interfaces create...
        if not step in args.__dict__:
            _build_cli_params()
            return
        next_step = args.__dict__[step] # -> create
        if not next_step in args.__dict__:
            cli_func_name += f'_{next_step}' # -> _interfaces_create
            _build_cli_params()
            return
        _build_cli_func(next_step)

    def _build_cli_module(step):
        nonlocal cli_module_name
        nonlocal cli_func_name

        if not step in args.__dict__:
            return
        cli_module_name += f'_{step}' # -> fwcli_configure -> fwcli_configure_router
        next_step = args.__dict__[step] # -> router -> interfaces
        if cli_module_name in fwglobals.cli_modules:
            _build_cli_func(next_step)
            cli_func_name = cli_func_name.lstrip('_') # _interfaces_create -> interfaces_create
            return
        _build_cli_module(next_step)

    _build_cli_module(args.command)

    if not cli_func_name:
        print(f'failed to identify function out of command')
        return -1

    # Call function either locally in context of "this" agent or remotely
    # in context of the running agent - see "fw_rpc"/"is_rpc".
    try:
        f = getattr(fwglobals.cli_modules[cli_module_name], cli_func_name)
        if not hasattr(f, 'is_rpc'):
            ret_val = f(**cli_params)
        else:
            # We are going to invoke function as RPC on running agent daemon.
            # Format command as a flexiManage->flexiEdge message.
            # This is needed to fit message queue handling infrastructure.
            #
            cli_message = {
                "message":         "cli-command",
                "cli_module_name": cli_module_name,
                "cli_func_name":   cli_func_name,
                "params":          cli_params,
            }
            # add special parameter - ID of application that calls CLI
            #
            if args.appl_id:
                cli_message.update({ "cli_appl_id": args.appl_id })

            reply = daemon_rpc('api', api_name='inject_requests', json_requests=cli_message)
            #
            # inject_requests() returns following object:
            #   {
            #     'seq': 12345
            #     'msg': {
            #         "ok":      [0|1]
            #         "message": <error string if "ok" is 0 or ''>
            #         "ret":     <return value of CLI target function or error string if "ok" is 0>
            #     }
            #   }
            #
            if not reply:
                raise Exception("inject_requests() didn't return reply")
            if reply.get('ok') == 0:
                err = reply.get('message', reply.get('ret', "unknown error"))
                raise Exception(err)
            ret_val = reply.get('ret', {})

        if ret_val:
            if isinstance(ret_val, dict):
                ret_str = json.dumps(ret_val, indent=2, sort_keys=True)
            else:
                ret_str = str(ret_val)
            print(ret_str)
        return 0            # shell OK

    except AttributeError as ae:
        print(f'error: handle_cli_command: {cli_func_name}({cli_params if cli_params else ""}) failed: {ae}')
        return -1           # shell ERROR
    except Exception as e:
        print(f'error: handle_cli_command: {cli_func_name}({cli_params if cli_params else ""}) failed with: {e}')
        return -1           # shell ERROR

def fw_rpc(func):
    '''This is a decorator for methods that are supposed be invoked from other process.
    The IPC is provided by the 3rd party module Pyro. We use "RPC", as Pyro supports RPC-s as well.
    '''
    func.is_rpc = True
    return func

if __name__ == '__main__':
    import argcomplete
    import argparse

    fwglobals.initialize()

    command_functions = {
        'version':lambda args: version(),
        'reset': lambda args: reset(soft=args.soft, quiet=args.quiet, pppoe=args.pppoe),
        'stop': lambda args: stop(stop_router=(not args.dont_stop_vpp), stop_applications=(not args.dont_stop_applications)),
        'start': lambda args: start(start_router=args.start_router, start_applications=args.start_applications),
        'daemon': lambda args: daemon(debug_conf_filename=args.debug_conf_filename, agent_conf_filename=args.agent_conf_filename),
        'simulate': lambda args: simulate(count=int(args.count) if args.count is not None else 1,
                                          reconnect=args.reconnect, delete=args.delete),
        'dump': lambda args: dump(filename=args.filename, path=args.path, clean_log=args.clean_log, full=args.full),
        'show': lambda args: show(
            agent=args.agent,
            configuration=args.configuration,
            database=args.database,
            status=args.status,
            networks=args.networks,
            watchdog=args.watchdog),
        'cli': lambda args: cli(
            script_fname=args.script_fname,
            clean_request_db=args.clean,
            api=args.api,
            template_fname=args.template_fname,
            ignore_errors=args.ignore_errors,
            fallback_to_local_agent=args.fallback_to_local_agent,
            quiet=args.quiet),
    }
    for cli_command_name in fwglobals.cli_commands.keys():
        command_functions.update({cli_command_name: lambda args: handle_cli_command(args)})

    parser = argparse.ArgumentParser(
        description="Device Agent for FlexiWan orchestrator\n" + \
                    "--------------------------------------------------------------\n" + \
                    "Use 'fwagent.py <command> --help' for help on specific command",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--appl_id', help="for internal use")

    subparsers = parser.add_subparsers(help='Agent commands', dest='command')
    subparsers.required = True
    parser_version = subparsers.add_parser('version', help='Show components and their versions')
    parser_reset = subparsers.add_parser('reset', help='Reset device: clear router configuration and remove device registration')
    parser_reset.add_argument('-s', '--soft', action='store_true',
                        help="clean router configuration only, device remains registered")
    parser_reset.add_argument('-q', '--quiet', action='store_true',
                        help="don't print info onto screen, print into syslog only")
    parser_reset.add_argument('-p', '--pppoe', action='store_true',
                        help="clean pppoe configuration")
    parser_stop = subparsers.add_parser('stop', help='Request daemon to stop agent connection to flexiManage')
    parser_stop.add_argument('-r', '--dont_stop_vpp', action='store_true',
                        help="stop agent without stopping the router")
    parser_stop.add_argument('-a', '--dont_stop_applications', action='store_true',
                        help="stop agent without stopping the applications")
    parser_stop.add_argument('-q', '--quiet', action='store_true',
                        help="don't print info onto screen, print into syslog only")
    parser_start = subparsers.add_parser('start', help='Request daemon to start agent connection to flexiManage')
    parser_start.add_argument('-q', '--quiet', action='store_true',
                        help="don't print info onto screen, print into syslog only")
    parser_start.add_argument('-r', '--start_router', action='store_true',
                        help="start router")
    parser_start.add_argument('-a', '--start_applications', action='store_true',
                        help="start applications")
    parser_daemon = subparsers.add_parser('daemon', help='Run agent in daemon mode: infinite register-connect loop')
    parser_daemon.add_argument('-d', '--debug_conf', dest='debug_conf_filename', default=None,
                        help="Path to debug_conf.yaml file, includes filename")
    parser_daemon.add_argument('-c', '--agent_conf', dest='agent_conf_filename', default=None,
                        help="Path to fwagent_conf.yaml file")
    parser_simulate = subparsers.add_parser('simulate', help='register and connect many fake devices with flexiManage')
    parser_simulate.add_argument('-c', '--count', dest='count',
                        help="How many devices to simulate")
    parser_simulate.add_argument('-r', '--reconnect', dest='reconnect', nargs='?', const=True,
                        help="reconnect to simulated devices")
    parser_simulate.add_argument('-d', '--delete', dest='delete', nargs='?', const=True,
                        help="clear the history and delete previously connected devices")
    parser_show = subparsers.add_parser('show', help='Prints various information to stdout')
    parser_show.add_argument('--agent', choices=['version', 'cache', 'threads'],
                        help="show various agent parameters")
    parser_show.add_argument('--configuration', const='all', nargs='?',
                        choices=['all', 'router', 'system', 'multilink-policy', 'signature', 'router-pending'],
                        help="show flexiEdge configuration")
    parser_show.add_argument('--networks', nargs='?', const='all',
                        choices=['all', 'lan', 'wan'],
                        help="show flexiEdge configuration")
    parser_show.add_argument('--database',
                        choices=['applications', 'firewall', 'frr', 'general', 'jobs', 'multilink', 'qos', 'router', 'system'],
                        help="show whole flexiEdge database")
    parser_show.add_argument('--status', choices=['daemon', 'router'],
                        help="show flexiEdge status")
    parser_show.add_argument('--watchdog', choices=['connection'],
                        help="show information for various watchdogs")


    parser_cli = subparsers.add_parser('cli', help='Runs agent in CLI mode: read flexiManage requests from command line')
    parser_cli.add_argument('-f', '--script_file', dest='script_fname', default=None,
                        help="File with requests to be executed")
    parser_cli.add_argument('-t', '--template', dest='template_fname', default=None,
                        help="File with substitutions for the script file, see -f")
    parser_cli.add_argument('-I', '--ignore_errors', dest='ignore_errors', action='store_true',
                        help="Ignore errors")
    parser_cli.add_argument('-c', '--clean', action='store_true',
                        help="clean request database on exit")
    parser_cli.add_argument('-i', '--api', dest='api', default=None, nargs='+',
                        help="fwagent API to be invoked with space separated arguments, e.g. '--api inject_requests filename=request.json'")
                        # If arguments include spaces escape them with slash, e.g. "--api inject_requests filename=my\ request.json"
                        # or surround argument with single quotes, e.g. "--api inject_requests 'filename=my request.json'"
                        # Note we don't use circle brackets, e.g. "--api inject_requests(request.json)" to avoid bash confuse
    parser_cli.add_argument('-l', '--local', dest='fallback_to_local_agent', action='store_true', default=False,
                        # "create local temporary instance of agent if daemon was not found" - FOR DEVELOPERS ONLY!
                        help=argparse.SUPPRESS)   # hide this parameter from "--help"!
    parser_cli.add_argument('-q', '--quiet', action='store_true', default=False,
                        help="don't print logs onto screen")
    parser_dump = subparsers.add_parser('dump', help='Dump various system info into x.tar.gz file')
    parser_dump.add_argument('-f', '--file', dest='filename', default=None,
                        help="The name of the result archive file. \n" +
                             "The default is 'fwdump', when hostname and timestamp are appended automatically.")
    parser_dump.add_argument('-p', '--path', dest='path', default=os.getcwd(),
                        help="The path to the final name. The default is cwd")
    parser_dump.add_argument('-c', '--clean_log', action='store_true',
                        help="Clean agent log")
    parser_dump.add_argument('--full', action='store_true',
                        help="Take full dump including all available logs")

    for cmd_name, cli_command in fwglobals.cli_commands.items():
      cli_parser     = subparsers.add_parser(cmd_name, help=cli_command['help'])
      cli_subparsers = cli_parser.add_subparsers(dest=cmd_name)
      for name in cli_command['modules']:
        fwglobals.cli_modules[name].argparse(cli_subparsers)

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if hasattr(args, 'quiet') and args.quiet:
        fwglobals.log.set_target(to_syslog=True, to_terminal=False)

    if not args.command in [ 'show', 'version' ]:
        if not fwutils.check_root_access():
            sys.exit(1)

    try:
        fwglobals.log.debug("---> exec " + str(args), to_terminal=False)
        ret = command_functions[args.command](args)
        if type(ret) == int:
            sys.exit(ret)
    finally:
        fwglobals.finalize()


