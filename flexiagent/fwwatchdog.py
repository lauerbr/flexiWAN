#! /usr/bin/python3

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

import copy
import json
import os
import re
import threading
import time
import traceback

import fwglobals
import fwnetplan
import fwrecover_connection
import fwutils

from fwobject import FwObject

class FwRlock():
    def __init__(self, name):
        self.lock    = threading.RLock()
        self.owner   = None
        self.counter = 0
        self.name    = f"{name}-{id(self)}" # for debugging purposes

    def locked(self):
        return bool(self.owner)

    def acquire(self):
        ret = self.lock.acquire()
        self.counter += 1
        if self.counter == 1:
            thread = threading.current_thread()
            self.owner = thread.ident
            with fwglobals.g.cache.thread_lock:
                thread_to_locks = fwglobals.g.cache.thread_to_locks
                if self.owner in thread_to_locks:
                    thread_to_locks[self.owner]['num_taken_locks'] += 1
                else:
                    thread_name = getattr(thread, 'name', "unnamed")
                    thread_to_locks.update({
                        self.owner: {
                            'num_taken_locks': 1,
                            'thread_name': thread_name
                        }
                    })
                fwglobals.g.cache.thread_lock_to_thread.update({self.name: self.owner})
        return ret

    def release(self):
        self.counter -= 1
        if self.counter == 0:
            with fwglobals.g.cache.thread_lock:
                thread_to_locks = fwglobals.g.cache.thread_to_locks
                thread_to_locks[self.owner]['num_taken_locks'] -= 1
                if thread_to_locks[self.owner]['num_taken_locks'] == 0:
                    del thread_to_locks[self.owner]
                del fwglobals.g.cache.thread_lock_to_thread[self.name]
            self.owner = None
        self.lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

class FwWatchdogDeadlock(FwObject):

    def watch(self, seconds):
        if seconds % fwglobals.g.DEADLOCK_PROBE_INTERVAL:
            return

        # Work on copy to avoid locking
        thread_locks = copy.deepcopy(fwglobals.g.cache.thread_to_locks)

        # If Message Handler thread handles received request,
        # which means there is undergoing router configuration, other threads might be blocked.
        # In this case, there is no need to monitor rest thread, check the configuration thread only.
        # Reset all the rest of threads to ensure no false detection.
        #
        thd = fwglobals.g.message_handler.thread_handle_messages
        if thd:
            curr_frame, line_found = fwutils.get_backtrace(thd.ident, "self._handle_received_request")
            if line_found:
                snapshots = fwglobals.g.cache.thread_snapshots
                counter  = snapshots.get(thd.name,{}).get('deadlock_probes', 0)
                if counter < fwglobals.g.DEADLOCK_THRESHOLD_PROBES:

                    prev_frame = snapshots.get(thd.name, {}).get('frame')
                    counter = 0 if curr_frame != prev_frame else counter + 1

                    if [s for s in curr_frame if re.search(r'rt\.request_cond_var.wait_for',s)]:
                        # If thread is blocked because there is undergoing configuration modification,
                        # e.g. start-router initiated by VPP watchdog, reset probe counter to prevent
                        # false alarm. The latest might happen if undergoing configuration is so heavy,
                        # that it takes more time then the deadlock detection threshold.
                        # In this case the message handling thread should wait on "request_cond_var".
                        #
                        counter = 0

                    fwglobals.g.cache.db['THREADS']['snapshots'].clear()
                    fwglobals.g.cache.db['THREADS']['snapshots'].update({
                        thd.name: {
                            'frame':            curr_frame,
                            'deadlock_probes':  counter
                            }
                        })
                    return

        # Now check all threads.
        #
        deadlock_detected = False
        for thd in threading.enumerate():

            if not thd.name.startswith('FwThread'):
                continue

            snapshots = fwglobals.g.cache.thread_snapshots
            curr_frame, _ = fwutils.get_backtrace(thd.ident)
            if not curr_frame:
                continue
            prev_frame = snapshots.get(thd.name, {}).get('frame')
            if curr_frame != prev_frame:
                snapshots.update({thd.name: {'frame': curr_frame, 'deadlock_probes': 0}})
            elif re.search(r'ssl|time\.sleep|sock\.sendto', curr_frame[-1]):
                # ignore waiting on sockets, timers and queues
                snapshots[thd.name]['deadlock_probes'] = 0
            elif thd.ident not in thread_locks:
                # If thread didn't take any lock yet, it is not deadlocked.
                # It probably waits for lock taken by other thread.
                #
                snapshots[thd.name]['deadlock_probes'] = 0
            else:
                snapshots[thd.name]['deadlock_probes'] += 1

            if snapshots[thd.name]['deadlock_probes'] > fwglobals.g.DEADLOCK_THRESHOLD_PROBES:
                self.log.excep(f"suspect for deadlock: {thd.name}: {snapshots[thd.name]['frame']}")
                deadlock_detected = True

        if deadlock_detected:
            snapshot_str = json.dumps(fwglobals.g.cache.thread_snapshots, indent=2, sort_keys=True, cls=fwutils.FwJsonEncoder)
            self.log.error(snapshot_str)
            self.log.excep("deadlock detected -> exit()")
            os._exit(os.EX_TEMPFAIL)   # os._exit() terminates the process, so systemd should restart the daemon again


class FwWatchdogConnection(FwObject):

    def __init__(self):
        FwObject.__init__(self)
        self.recovery             = fwrecover_connection.FwRecoverConnection()
        self.reconnect_failures   = fwglobals.g.db.fetch('watchdog/connection/reconnect_failures', default_val=0)
        self.router_cfg_signature = None

    def watch(self, _):
        if fwglobals.g.cfg.WATCHDOG_ROUTER_CFG_WINDOW > 0:
            signature = fwutils.get_device_config_signature()
            if signature != self.router_cfg_signature:
                self.router_cfg_signature = signature
                self.recovery.router_cfg_changed_at = time.time()

    def update_connection_status(self, connected):

        if not connected and fwglobals.g.router_api.state_is_starting_stopping():
            return

        self.reconnect_failures = 0 if connected else self.reconnect_failures + 1
        fwglobals.g.db.put('watchdog/connection/reconnect_failures', self.reconnect_failures)

        if connected:
            fwnetplan.generate_recovery_netplan()

        if self.recovery.is_idle():
            if self.reconnect_failures < 2:
                return      # Ignore the first failure - give it one more chance
            if fwglobals.g.wan_monitor.check_internet(use_default_threshold=False, time_window=120, min_probes=5):
                return      # If WAN Monitor has at least one not dead WAN interface in last 2 minutes, don't recover
            start_time = time.time()
            fwutils.fwdump(filename="connection_recovery")
            self.recovery.start(start_time=start_time)
        else:
            self.recovery.update_connection_status(connected)

    def get_connection_recovery_state(self):
        return self.recovery.get_state()

class FwWatchdog(FwObject):
    """This class is dispatcher for all kind watchdogs in agent.
    It runs 1 sec loop and invokes routines of specialized watchdogs.
    """
    def __init__(self):
        FwObject.__init__(self)
        self.thread_watchdog = None
        self.thread_deadlock = None  # Use separate thread for the Deadlock watchdog to ensure no locks
        self.watchdogs = [
            FwWatchdogConnection(),
        ]
        self.connection_watchdog = self.watchdogs[0]
        self.deadlock_watchdog   = FwWatchdogDeadlock()
        self.teardown            = False


    def start(self):
        self.teardown = False
        if not self.thread_deadlock and fwglobals.g.cfg.WATCHDOG_DEADLOCK_ENABLED:
            self.thread_deadlock = threading.Thread(target=self._watchdog, name='FwWatchdogDeadlock', args=([[self.deadlock_watchdog]]))
            self.thread_deadlock.start()
        if not self.thread_watchdog and fwglobals.g.cfg.WATCHDOG_CONNECTION_ENABLED: # as we have Connection watchdog only today, suppress whole thread if Connection watchdog is disabled
            self.thread_watchdog = threading.Thread(target=self._watchdog, name='FwWatchdog', args=([self.watchdogs]))
            self.thread_watchdog.start()

    def stop(self):
        self.teardown = True
        if self.thread_watchdog:
            self.thread_watchdog.join()
            self.thread_watchdog = None
        if self.thread_deadlock:
            self.thread_deadlock.join()
            self.thread_deadlock = None

    def update_connection_status(self, connected):
        try:
            if self.thread_watchdog:   # ensure the watchdog was started
                self.connection_watchdog.update_connection_status(connected)
        except Exception as e:
            self.log.excep(f"update_connection_status: {e} ({traceback.format_exc()})")
            # don't propagate watchdog exceptions to other thread

    def get_connection_recovery_state(self):
        return str(self.watchdogs[0].get_connection_recovery_state())

    def _watchdog(self, watchdogs):
        seconds = 0
        while not self.teardown:
            for wd in watchdogs:
                try:
                    wd.watch(seconds)
                except Exception as e:
                    fwglobals.g.log.error(f"{wd} failed: {e} ({traceback.format_exc()})")
            seconds += 1
            time.sleep(1)   # Check self.active every second to detect Ctrl-C ASAP
