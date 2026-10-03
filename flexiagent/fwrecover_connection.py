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

import enum
import json
import time

import fwglobals
import fwnetplan
import fwutils

from fwobject import FwObject


class FwRecoveryState(enum.Enum):
    IDLE        = 1
    IN_PROGRESS = 2
    FAILED      = 3
    DISABLED    = 4
    RECOVERED   = 5

class _RecoverAbstract(FwObject):
    '''The _RecoverAbstract provides abstraction of recovery method used to recover from
    the broken agent-to-flexiManage connection.
        Recovery method is an object that runs some actions in order to ensure success
    of re-connection to flexiManage. We call this object 'Recovery'. Various Recoveries implement
    different approaches to ensure connection recovering. For example, the _RecoverNetplan Recovery
    applies last working netplan yaml, the _RecoverAutosense Recovery resets the autosense feature
    to factory default configuration, etc.
        All recoveries implement same API for controlling and monitoring the recovery process,
    like start(), stop(), etc. The  _RecoverAbstract object defines this API.
        All recoveries are registered with and managed by the FwRecoverConnection object.
    It decides which recovery to use and when. Today it simply iterates over list of Recoveries,
    while having only one of them active at any given moment. If active recovery reports failure
    to recover the connection, the FwRecoverConnection starts next recovery in list.
    '''
    def __init__(self, recover):
        FwObject.__init__(self)
        self.state              = FwRecoveryState.IDLE
        self.reconnect_failures = 0
        self.recover            = recover
        self._restore()

    def __str__(self):
        return self.name

    def start(self):
        self.reconnect_failures = 0
        self._change_state(FwRecoveryState.IN_PROGRESS)
        self._store()

    def stop(self, recovered):
        state = FwRecoveryState.IDLE if recovered else FwRecoveryState.FAILED
        self._change_state(state)
        self._store()

    def handle_reconnect_failed(self):
        self.reconnect_failures += 1
        if self.reconnect_failures == 2:  # give two trials to connect after the recovery was initiated
            self._change_state(FwRecoveryState.FAILED)
        self._store()

    def _change_state(self, state):
        self.log.debug(f'{self.state} -> {state}')
        self.state = state

    def _store(self):
        '''Serializes this recovery onto disk'''
        # We don't serialize whole self, as this function is called by FwRecoverConnection::store() ,
        # and self, has reference to FwRecoverConnection object, so
        # json.dumps(self, cls=fwutils.FwJsonEncoderFwObject) will encounter circular dependency.
        #
        #serialized = json.dumps(self, cls=fwutils.FwJsonEncoderFwObject)
        self_reduced = {'state':self.state, 'reconnect_failures': self.reconnect_failures}
        serialized = json.dumps(self_reduced, cls=fwutils.FwJsonEncoderFwObject)
        fwglobals.g.db.put(f'recovery/connection/{self}', serialized)

    def _restore(self):
        '''Deserializes this recovery from disk'''
        serialized = fwglobals.g.db.fetch(f'recovery/connection/{self}')
        if serialized:
            fwutils.deserialize(self, serialized)

class _RecoverRouterConfiguration(_RecoverAbstract):
    '''The _RecoverRouterConfiguration implements recovery of agent-to-flexiManage connection,
    if the connection was lost due to bad user configuration.
        As it is pretty hard to ensure that the reason for connection lose is user configuration,
    we just adopt some simple heuristics: if configuration was changed in last 4 minutes,
    and VPP runs, so the user configuration has impact, and DNS resolution for flexiManage URI works,
    then we assume the connection was lost due to configuration change.
        The Recovery just stops the VPP, so the Linux networking should take care.
        As stopping VPP has bad impact on traffic, user can disable this Recovery by setting
    the 'router_cfg_window' parameter in fwagent_conf.yaml to 0. As well, it can be adjusted to any
    time the user consider could fit the production.
    '''
    def start(self):
        if not self.recover.router_cfg_changed_at:
            self.log.debug("router configuration was not changed since watchdog start")
            return

        elapsed = self.recover.started_at - self.recover.router_cfg_changed_at
        window  = fwglobals.g.cfg.WATCHDOG_ROUTER_CFG_WINDOW
        if elapsed > window:
            self.log.debug(f"router configuration was not changed in last {window} seconds")
            return # probably configuration change is not related to disconnection

        if not fwglobals.g.router_api.state_is_started():
            self.log.debug("VPP does not run")
            return

        # In contradiction to other types of recovery cases, there is no need
        # to check internet reachability, as there are good chances user screwed up
        # vRouter configuration - by improper policies, bad static routes, etc.
        # And if user don't want us to stop VPP, so the bad configuration will persist,
        # other types of recovery will not help. To prevent agent to run other types of
        # recovery we mark this recovery as 'disabled' and we will check this flag
        # while picking up next recovery type.
        #
        if fwglobals.g.cfg.WATCHDOG_ROUTER_CFG_WINDOW == 0:   # '0' means 'disabled by user'
            self._change_state(FwRecoveryState.DISABLED)
            return

        _RecoverAbstract.start(self)
        fwglobals.g.router_api.stop_router("connection recovery")


class _RecoverNetplan(_RecoverAbstract):
    '''The _RecoverNetplan implements recovery of agent-to-flexiManage connection,
    if the connection was lost due to bad netplan configuration.
        As user can't manipulate netplan file directly, when VPP runs,
    this Recovery happens only if VPP does not run. It is needed to handle cases,
    where device was configured in lab, then was moved to the field, but Linux configuration was
    not adjusted to the new place.
        This Recovery replaces the current netplan yaml-s with the recovery netplan yaml.
    The latest is created every time the connection succeeded, either when VPP runs or not.
    It includes the minimal possible interface configuration that provide access to internet.
    To do this magic, it just fetches the device from the default route and stores it's parameters
    into recovery yaml.
    '''
    def start(self):
        if fwglobals.g.router_api.state_is_started():
            self.log.debug("VPP runs, can't recover")
            return
        err_str = fwnetplan.validate_recovery_netplan()
        if err_str:
            self.log.debug(f"recovery yaml can't be applied: {err_str}")
            return

        _RecoverAbstract.start(self)

        if fwglobals.g.cfg.debug['agent']['features']['autosense']['enabled']:
            fwutils.exec("fwautosense -q --disable", logger=self.log)

        fwnetplan.start_recovery_netplan()

class _RecoverAutosense(_RecoverAbstract):
    '''The _RecoverAutosense implements recovery of agent-to-flexiManage connection,
    if the connection was lost due to bad network configuration, and if _RecoverNetplan failed.
    It just restores the factory settings, effectively launching external DHCP client on all
    available interfaces.
        This Recovery runs only if VPP does not run.
    '''
    def start(self):
        if fwglobals.g.router_api.state_is_started():
            self.log.debug("VPP runs, can't recover")
            return
        _RecoverAbstract.start(self)
        fwutils.exec("fwautosense -q --factory", logger=self.log)

class _RecoverReboot(_RecoverAbstract):
    '''The _RecoverReboot is the last chance recovery, which just reboots the system.
    Hopefully that will restore the connectivity.
    '''
    def start(self):
        _RecoverAbstract.start(self)
        fwutils.exec("reboot now")


class FwRecoverConnection(FwObject):
    '''Encapsulates and manages various types of recovery that run when connection of agent
    to flexiManage is lost. For example, it might run _RecoverNetplan recovery.
    When all types of recovery were tried and all of them failed to recover the connection,
    the FwRecoverConnection moves to the FAILED state. On success, it moves to the IDLE state.
    The recovery process can be re/started by calling 'start()' method. This moves the object
    to IN_PROGRESS state.
    '''
    def __init__(self):
        FwObject.__init__(self)
        self.state           = FwRecoveryState.RECOVERED if fwnetplan.was_recovery_netplan_started() else FwRecoveryState.IDLE
        autosense_enabled    = fwglobals.g.cfg.debug['agent']['features']['autosense']['enabled']
        self.recoveries      = [
            _RecoverRouterConfiguration(self),
            _RecoverNetplan(self),
            _RecoverAutosense(self),
            _RecoverReboot(self),
        ] \
        if autosense_enabled else \
        [
            _RecoverRouterConfiguration(self),
            _RecoverNetplan(self),
        ]
        self.active_recovery    = self._restore_active_recovery()
        self.router_cfg_changed_at = None
        self.started_at            = None

    def _change_state(self, state, reason=""):
        log_line = f'{self.state} -> {state} ({reason})' if reason else \
                   f'{self.state} -> {state}'
        self.log.debug(log_line)
        self.state = state
        self._store_active_recovery()

    def _store_active_recovery(self):
        '''Serializes and stores the active recovery on disk'''
        fwglobals.g.db.put( 'recovery/connection/state', str(self.state.name))
        if self.active_recovery:
            fwglobals.g.db.put( 'recovery/connection/active_recovery', str(self.active_recovery))
        else:
            fwglobals.g.db.delete( 'recovery/connection/active_recovery')

    def _restore_active_recovery(self):
        '''Restores and deserializes the active recovery from disk'''
        state_str  = fwglobals.g.db.fetch('recovery/connection/state')
        self.state = FwRecoveryState[state_str] if state_str else FwRecoveryState.IDLE
        recovery_str = fwglobals.g.db.fetch( 'recovery/connection/active_recovery')
        if recovery_str:
            for r in self.recoveries:
                if str(r) == recovery_str:
                    return r
            self.log.excep(f'failed to restore recovery by name={recovery_str}')
        return None

    def is_idle(self):
        return (self.state == FwRecoveryState.IDLE)

    def start(self, start_time):
        self.log.debug("start recovery")
        self.started_at = start_time if start_time else time.time()

        if self.active_recovery:
            self.active_recovery.stop(recovered=False)
            self.active_recovery = None

        for recovery in self.recoveries:
            recovery.start()
            if recovery.state == FwRecoveryState.IN_PROGRESS:
                self.active_recovery = recovery
                break
            if recovery.state == FwRecoveryState.DISABLED and \
               isinstance(recovery, _RecoverRouterConfiguration):
                # Take a special care of the case, where Recovery of bad Router Configuration
                # would run (and would stop VPP in order to try to recover),
                # but it was disabled by user. In this case we should stop trials to recover
                # connection by any type of recovery, as any type of recovery assumes change
                # of vRouter configuration. And if vRouter configuration is changed, it will become
                # out of sync with configuration stored on flexiManage. This is forbidden state.
                # flexiManage will try to fix it using 'sync-device' request, thus cancelling
                # the recovery effect. To avoid flapping of connectivity due to configuration sync,
                # stop the whole recovery process.
                #
                self.log.debug(f"disabling recovery was encountered: {recovery} -> stop recovering")
                break
            else:
                self.log.debug(f"skip {recovery}")

        new_state = FwRecoveryState.IN_PROGRESS if self.active_recovery else FwRecoveryState.FAILED
        self._change_state(new_state)

    def get_state(self):
        return self.state.name

    def update_connection_status(self, connected):
        if self.active_recovery:  # don't flood log
            self.log.debug(f"connected={connected}, active_recovery={self.active_recovery}")

        if connected:
            if self.active_recovery:
                self.active_recovery.stop(recovered=True)
                self.active_recovery = None
            self._change_state(FwRecoveryState.RECOVERED if fwnetplan.was_recovery_netplan_started() else FwRecoveryState.IDLE)
            return

        if self.state == FwRecoveryState.FAILED:
            # If recovery failed and connection was not connected after that, we can't help
            return

        # Feed the current recovery case with the 'reconnection failed' status,
        # check its state and if it finished (not IN_PROGRESS), move to the next recovery case.
        # The loop below skips recovery cases that are not able even to start recovery
        # due to some conditions that are specific to the case. These recovery
        # cases should be in non-IN_PROGRESS state right after start().
        #
        self.active_recovery.handle_reconnect_failed()
        while self.active_recovery.state != FwRecoveryState.IN_PROGRESS:
            if self.active_recovery == self.recoveries[-1]:
                self.active_recovery = None
                self._change_state(FwRecoveryState.FAILED)
                return
            next_idx = self.recoveries.index(self.active_recovery) + 1
            self.active_recovery = self.recoveries[next_idx]
            self._change_state(FwRecoveryState.IN_PROGRESS, f'trying {self.active_recovery}')  # Call this before start()! It dumps data onto disk
            self.active_recovery.start()
