#! /usr/bin/python

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

import copy
import glob
import importlib
import os
import pathlib
import json
import threading

import fwglobals
import fwthread
from fwapplications_cfg import FwApplicationsCfg
from fwcfg_request_handler import FwCfgRequestHandler

fwapplication_translators = {
    'add-app-install':        {'module': __import__('fwtranslate_add_app_install'),   'api':'add_app_install'},
    'remove-app-install':     {'module': __import__('fwtranslate_revert') ,           'api':'revert'},
    'add-app-config':         {'module': __import__('fwtranslate_add_app_config'),    'api':'add_app_config'},
    'remove-app-config':      {'module': __import__('fwtranslate_revert'),            'api':'revert'},
}

fwappliation_getters = {
    'exec-app-action':           '_exec_application_action',
}

class FWAPPLICATIONS_API(FwCfgRequestHandler):
    """Services class representation.
    """

    def __init__(self):
        """Constructor method.
        """
        # FWAPPLICATIONS_API can be called without globals initialization.
        self.fwglobals_initialized_by_me = False
        if not fwglobals.g:
            fwglobals.initialize()
            self.fwglobals_initialized_by_me = True

        cfg = FwApplicationsCfg()
        FwCfgRequestHandler.__init__(self, fwapplication_translators, cfg)

        self.api_tracker = FwApplicationsTracker(fwglobals.g.APPLICATIONS_TRACKER_FILE)

        self.thread_applications = None
        self.thread_interval     = 10

        self.processing_request = False

        self.stats    = {}

        self.app_instances = {}

        self._build_app_instances()

        self.applications_started = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        return

    def initialize(self):
        self.start_applications_thread()
        super().initialize()

    def finalize(self):
        self.stop_applications_thread()
        self.app_instances = {}
        super().finalize()
        if self.fwglobals_initialized_by_me:
            fwglobals.finalize()


    def start_applications_thread(self):
        if not self.thread_applications:
            self.thread_applications = fwthread.FwThread(target=self._applications_thread_func, name='Applications', log=self.log)
            self.thread_applications.start()

    def stop_applications_thread(self):
        if self.thread_applications:
            self.thread_applications.stop()
            self.thread_applications = None

    def stop_applications(self):
        self.applications_started = False # to stop the watchdog hook that can restart applications
        self.call_hook('stop')

    def start_applications(self):
        self.call_hook('start')
        self.applications_started = True

    def call(self, request, dont_revert_on_failure=False):
        req    = request['message']
        # Try first to get getter handler
        handler = fwappliation_getters.get(req, None)
        # If not found call parent conf handler
        if not handler:
            return FwCfgRequestHandler.call(self, request, dont_revert_on_failure)

        # Else call local getter
        params = request.get('params')
        handler_func = getattr(self, handler)
        assert handler_func, 'fwapplication_api: handler=%s not found for req=%s' % (handler, req)

        reply = handler_func(params)
        if reply['ok'] == 0:
            self.log.error(f"fwapplication_api: {handler}({format(params)}) failed: {reply['message']}")
            raise Exception(reply['message'])
        return reply

    def _exec_application_action(self, params):
        '''
        {
            "params": {
                "identifier": "com.flexiwan.monitorntop",
                "applicationApi": "get_active_flows",
                "applicationParams": { ... }
            }
        }
        '''
        identifier = params.get('identifier')
        return self._call_application_api_safe(identifier, 'exec_application_action',
                                               params=params, default_ret={'ok':0, 'message':'Application api not found'})

    def _build_app_instances(self):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        installed_apps = glob.glob(f'{current_dir}/applications/com_flexiwan_*')

        for installed_app in installed_apps:
            try:
                module_name = installed_app.split('/')[-1]
                spec = importlib.util.spec_from_file_location(module_name, installed_app + '/application.py')
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                instance = getattr(module, 'Application')
                app = instance()

                self.app_instances[app.identifier] = app
            except Exception as e:
                self.log.error(f'Application module not found for {module_name}, err: {str(e)}, skipping...')

    def _call_simple(self, request, execute=True, filter=None):
        try:
            self.processing_request = True
            FwCfgRequestHandler._call_simple(self, request, execute=execute, filter=filter)
            return {'ok':1}
        except Exception as e:
            err_str = f"FWAPPLICATIONS_API::_call_simple: {str(e)}"
            self.log.error(err_str)
            raise e
        finally:
            self.processing_request = False

    def install(self, params):
        '''
        {
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "applicationParams": {
                    "configParams": { ... }
                }
            }
        }
        '''
        identifier = params.get('identifier')

        installation_dir = self._get_installation_dir(identifier)
        if not os.path.exists(installation_dir):
            raise Exception(f'install file ({installation_dir}) is not exists')

        application_params = {'params': params.get('applicationParams')}
        self._call_application_api(identifier, 'install', application_params)

    def uninstall(self, params):
        '''
        {
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "applicationParams": {}
            }
        }
        '''
        identifier = params.get('identifier')

        application_params = params.get('applicationParams')
        self._call_application_api(identifier, 'uninstall', application_params)

        # remove application stats
        app_stats = self.stats.get(identifier)
        if app_stats:
            del self.stats[identifier]

    def configure(self, params):
        '''
        {
            "params": {
                "name": "Remote Worker VPN",
                "identifier": "com.flexiwan.remotevpn",
                "routeAllTrafficOverVpn": true,
                "port": "1194",
                ...
            }
        }
        '''
        identifier = params.get('identifier')

        application_params = {'params': params.get('applicationParams')}
        self._call_application_api(identifier, 'configure', application_params)

    def get_stats(self):
        return copy.deepcopy(self.stats)

    def _applications_thread_func(self, ticks):
        if fwglobals.g.router_api.state_is_starting_stopping():
            return

        if self.processing_request:
            return

        call_stats = ticks % self.thread_interval == 0
        call_watchdog = ticks % self.thread_interval == 0 and self.applications_started

        if not call_stats and not call_watchdog:
            return

        apps = self.cfg_db.get_applications()
        for app in apps:
            identifier = app['identifier']
            if call_watchdog:
                self._call_application_api(identifier, 'on_watchdog')

            if call_stats:
                new_stats = {}
                new_stats['running']    = self._call_application_api_safe(identifier, 'is_app_running', default_ret=False)
                new_stats['statistics'] = self._call_application_api_safe(identifier, 'get_statistics', default_ret={})
                self.stats[identifier]  = new_stats

        if not apps and self.stats:
            self.stats = {}

    def _call_application_api(self, identifier, method, params=None):
        if not identifier:
            raise Exception("identifier is required")

        self.api_tracker.save(identifier)
        try:
            app = self.app_instances[identifier]
            func = getattr(app, method, None)
            if not func:
                return True
            ret = func(**params) if params else func()
            return ret
        finally:
            self.api_tracker.delete(identifier)

    def _call_application_api_safe(self, identifier, method, params=None, default_ret=None):
        try:
            ret = self._call_application_api(identifier, method, params=params)
            return ret
        except Exception as e:
            self.log.error(f'_call_application_api_safe({identifier}, {method}, {str(params)}): {str(e)}')
            return default_ret

    def reset(self):
        self.call_hook('uninstall')
        self.cfg_db.clean()

    def call_hook(self, hook_name, params=None, identifier=None):
        res = {}
        apps = self.cfg_db.get_applications()
        for app in apps:
            app_identifier = app['identifier']

            if identifier and identifier != app_identifier:
                continue

            try:
                ret = self._call_application_api(app_identifier, hook_name, params)
                if ret:
                    res[app_identifier] = ret
            except Exception as e:
                self.log.debug(f'call_hook({hook_name}, {identifier}): failed for identifier={app_identifier}: err={str(e)}')

        return res

    def get_interfaces(self, **params):
        return self.call_hook('get_interfaces', params)

    def get_networks(self, **params):
        return self.call_hook('get_networks', params)

    def _get_installation_dir(self, identifier):
        current_dir = str(pathlib.Path(__file__).parent.resolve())
        identifier = identifier.replace('.', '_') # python modules cannot be imported if the path is with dots
        source_installation_dir = current_dir + '/applications/' + identifier
        return source_installation_dir

    def get_log_filename(self, identifier):
        return self._call_application_api_safe(identifier, 'get_log_filename')

def call_applications_hook(hook, identifier=None, params=None):
    '''This function calls a function within applications_api even if the agent object is not initialized
    '''
    # when calling this function from fwdump, there is no "g" in fwglobals
    if hasattr(fwglobals.g, 'applications_api'):
        return fwglobals.g.applications_api.call_hook(hook, identifier=identifier, params=params)

    with FWAPPLICATIONS_API() as applications_api:
        return applications_api.call_hook(hook, identifier=identifier, params=params)

class FwApplicationsTracker:
    """Wraps text file with application identifiers. The identifiers are recorded into this file
    before invocation application's API and are deleted from it after application's API returns.
    This is needed to prevent deadlock between fwagent daemon process and application process,
    which might happen as follows for example: request is received from flexiManage, it takes
    global lock (handle_request_lock) and triggers application code to invoke fwagent cli
    (fwgent configure ....) in a separate shell. This shell process is blocked on the global lock,
    so it does not return. And the request handling waits for shell process to return.
    """
    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.Lock()
        with open(self.filename, 'w', encoding="utf-8") as f:
            json.dump({"last_saved": [], "applications": {}}, f)

    def _load_data(self):
        with open(self.filename, 'r', encoding="utf-8") as f:
            return json.load(f)

    def _save_data(self, data):
        with open(self.filename, 'w', encoding="utf-8") as f:
            json.dump(data, f)

    def save(self, identifier):
        with self.lock:
            data  = self._load_data()
            apps  = data["applications"]

            if identifier in apps:
                apps[identifier] += 1
            else:
                apps[identifier] = 1
            self._save_data(data)

    def delete(self, identifier):
        with self.lock:
            data  = self._load_data()
            apps  = data["applications"]

            if identifier not in apps:
                raise Exception(f"FwApplicationsTracker.delete(): '{identifier}' not found")

            apps[identifier] -= 1
            if apps[identifier] <= 0:
                del apps[identifier]
            self._save_data(data)

    def check(self, identifier):
        with self.lock:
            data  = self._load_data()
            apps  = data["applications"]
            return (apps.get(identifier, 0) > 0)
