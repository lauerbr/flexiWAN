################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2024  flexiWAN Ltd.
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
import socket
import uuid
import time
import threading

import fwglobals
import fwthread
import fwutils

from fwobject import FwObject

RESOLUTION_COUNT    = 5     # Max number of FQDN-s to resolve in one pass
RESOLUTION_TIMEOUT  = 10    # Max time (in seconds) to wait for DNS resolution in one pass

class FwFqdnResolver(FwObject):
    def __init__(self):
        FwObject.__init__(self)
        self.db = fwglobals.g.db
        self.db_prefix = 'fqdn_resolver'
        self.thread_monitor_fqdn = None
        self.lock = threading.RLock() # RLock since callbacks can call "set" or "unset"
        self.lookup_threads = {}      # FQDN -> thread that runs DNS lookup, see _resolve()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        return

    def initialize(self):
        if not self.thread_monitor_fqdn:
            self.thread_monitor_fqdn = fwthread.FwRouterThread(self.monitor_thread_func, 'FQDN Resolver', self.log)
            self.thread_monitor_fqdn.start()
        super().initialize()

    def finalize(self):
        if self.thread_monitor_fqdn:
            self.thread_monitor_fqdn.join()
            self.thread_monitor_fqdn = None
        super().finalize()

    def clean(self):
        self.db.delete(self.db_prefix)

    def set(self, fqdn, func_module=None, func_name=None, func_params=None, result_cache=None):
        with self.lock:
            db_key = f'{self.db_prefix}/{fqdn}'
            current_fqdn = self.db.fetch(db_key)
            if not current_fqdn:
                current_fqdn = { 'ips': [], 'callbacks': { }, 'last_resolution': None, 'execute_callbacks': False }
            else:
                current_fqdn['execute_callbacks'] = True

            callback_id = None
            if func_module and func_name:
                callback_id = str(uuid.uuid4())
                current_fqdn['callbacks'][callback_id] = {
                    'func_module': func_module,
                    'func_name'  : func_name,
                    'func_params': func_params

                }

            self.db.put(db_key, current_fqdn)

            # Store 'callback_id' in cache if provided by caller.
            #
            if result_cache and result_cache['result_attr'] == 'callback_id' and callback_id:
                result_cache['cache']['callback_id'] = callback_id

    def get(self, fqdn):
        current_fqdn = self.db.fetch(f'{self.db_prefix}/{fqdn}', {})
        return current_fqdn.get('ips', [])

    def unset(self, fqdn, callback_id=None, keep_resolution=False):
        with self.lock:

            db_key = f'{self.db_prefix}/{fqdn}'
            current_fqdn = self.db.fetch(db_key)
            if not current_fqdn:
                return

            # Trigger the remove callback by setting empty IP list
            if not keep_resolution:
                self._handle_fqdn_change(fqdn, current_fqdn, [])

            if not callback_id:
                return

            if callback_id in current_fqdn['callbacks']:
                del current_fqdn['callbacks'][callback_id]
                self.db.delete(f'{self.db_prefix}/{fqdn}/callbacks/{callback_id}')
            else:
                self.log.error(f'The provided callback_id ({callback_id}) was not found')
                raise Exception('The provided callback_id was not found')

    def _exec_dns_lookup(self, fqdn):
        try:
            _, _, ip_addr_list = socket.gethostbyname_ex(fqdn)
            return ip_addr_list
        except socket.gaierror:
            return []
        except Exception as e:
            self.log.error(f'failed to execute DNS Lookup for {fqdn}: {e}')
            return []

    def _get_fqdns_to_resolve(self):
        """Returns list of FQDN-s that should be resolved in this pass."""
        fqdns_to_resolve = []
        fqdns = dict(self.db.fetch(self.db_prefix, {}))
        for fqdn, data in fqdns.items():
            if len(fqdns_to_resolve) >= RESOLUTION_COUNT:
                break

            callbacks            = data.get('callbacks')
            last_resolution      = data.get('last_resolution')

            if not callbacks:
                continue

            if last_resolution and (time.time() - last_resolution) < fwglobals.g.cfg.FQDN_RESOLUTION_INTERVAL:
                continue

            fqdns_to_resolve.append(fqdn)
        return fqdns_to_resolve

    def _resolve(self, fqdns):
        """Resolves FQDN-s simultaneously with timeout.
        The socket.gethostbyname_ex() has no timeout, so every lookup is run
        by dedicated daemon thread, and we wait for them no more than RESOLUTION_TIMEOUT.
        Daemon threads that did not finish in time do not block the agent exit.

        :returns: dictionary of FQDN -> list of IP-s. FQDN-s that were not
                  resolved in time are not included.
        """
        results = {}
        def _lookup(fqdn):
            results[fqdn] = self._exec_dns_lookup(fqdn)

        # Forget finished lookups of previous passes.
        #
        for fqdn, thread in list(self.lookup_threads.items()):
            if not thread.is_alive():
                del self.lookup_threads[fqdn]

        threads = []
        for fqdn in fqdns:
            if fqdn in self.lookup_threads:
                continue    # lookup started on previous pass still hangs, don't start one more
            thread = threading.Thread(target=_lookup, args=(fqdn,), name=f'FQDN lookup {fqdn}', daemon=True)
            thread.start()
            self.lookup_threads[fqdn] = thread
            threads.append(thread)

        deadline = time.monotonic() + RESOLUTION_TIMEOUT
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))

        resolved = {}
        for fqdn in fqdns:
            if fqdn in results:
                resolved[fqdn] = results[fqdn]
            else:
                self.log.debug(f'DNS lookup for {fqdn} was not finished in time, retry on next pass')
        return resolved

    def monitor_thread_func(self, ticks):
        if not fwglobals.g.router_api.state_is_started():
            return

        with self.lock:
            fqdns_to_resolve = self._get_fqdns_to_resolve()
        if not fqdns_to_resolve:
            return

        # Resolve out of lock, as DNS lookups might take long time,
        # and configuration requests might need the lock to call set() or unset().
        #
        resolved = self._resolve(fqdns_to_resolve)

        with self.lock:
            checked_keys = []
            fqdns = dict(self.db.fetch(self.db_prefix, {}))
            for fqdn, ip_addresses in resolved.items():

                # The FQDN might be removed or changed while we resolved it,
                # so use the updated data.
                #
                data = fqdns.get(fqdn)
                if not data or not data.get('callbacks'):
                    continue

                current_ip_addresses = data.get('ips')
                execute_callbacks    = data.get('execute_callbacks')

                checked_keys.append(fqdn)
                self._update_db(fqdn, 'last_resolution', time.time())

                # compare two lists regardless of order, hence use "set"
                if set(current_ip_addresses) == set(ip_addresses) and not execute_callbacks:
                    continue

                self._handle_fqdn_change(fqdn, data, ip_addresses)

            # now, put the checked FQDNs at the end of the dict
            fqdns = dict(self.db.fetch(self.db_prefix, {}))
            for checked_key in checked_keys:
                value = fqdns.pop(checked_key, None)
                if value is not None:
                    fqdns[checked_key] = value
            self.db.put(self.db_prefix, fqdns)

    def _update_db(self, fqdn, key, value):
        current_fqdn = self.db.fetch(f'{self.db_prefix}/{fqdn}')
        if not current_fqdn:
            return
        self.db.put(f'{self.db_prefix}/{fqdn}/{key}', value)

    def _handle_fqdn_change(self, fqdn, data, ip_addresses):
        current_ip_addresses = data.get('ips')

        self.log.debug(f'Change detected in the resolved IPs for {fqdn}: {current_ip_addresses} -> {ip_addresses}')

        self._update_db(fqdn, 'ips', ip_addresses)

        callbacks = data.get('callbacks', {})
        for callback in callbacks.values():
            func_module = callback.get('func_module')
            func_name   = callback.get('func_name')
            func_params = callback.get('func_params', {})

            final_params = {
                'prev_ip_addresses': current_ip_addresses,
                'ip_addresses': ip_addresses,
                **func_params
            }

            try:
                fwutils.call_function_by_names(func_module, func_name, **final_params)
            except Exception as e:
                self.log.error(f'failed to call callback({func_module}, {func_name}, {func_params}): {e}')

        self._update_db(fqdn, 'execute_callbacks', False)
