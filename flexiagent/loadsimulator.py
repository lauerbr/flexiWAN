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

import threading
import uuid
import fwglobals
import random
import time
import signal
import os
import psutil

import fwagent

from fwstats import UPDATE_LIST_MAX_SIZE
from fwobject import FwObject

class LoadSimulator(FwObject):
    """This is a load simulator class.
       It is used to emulate a big number of fake devices.
    """
    def __init__(self):
        """Constructor method
        """
        FwObject.__init__(self)
        self.started = False
        self.simulate_agents = []
        self.simulate_threads = []
        self.simulate_stats = {'tx_pkts': 0, 'tx_bytes': 0, 'rx_bytes': 0, 'rx_pkts': 0}
        self.simulate_tunnel_stats = {"1": {"status": "up", "rtt": 10, "drop_rate": 0}}
        self.interface_wan = '0000:00:03.00'
        self.interface_lan = '0000:00:08.00'
        self.thread_statistics = None
        self.db = fwglobals.g.create_sqlite_dict(fwglobals.g.DATA_PATH + '.simulate_device_info.sqlite')

        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)

    def _signal_handler(self, signum, frame):
        self.log.info("got %s" % fwglobals.g.signal_names[signum])
        self.stop()

    def stop(self):
        """Stop simulated devices.

        :returns: None.
        """
        self.started = False

        for agent in self.simulate_agents:
            agent.ws.disconnect()
        self.simulate_agents = []

        for t in self.simulate_threads:
            t.join()
        self.simulate_threads = []
        fwglobals.g.destroy_agent()



    def start(self, count, reconnect=None):
        """Starts the simulation.

        :param count: number of the simulated devices.
        """
        # We have to initialize agent once, as it initializes various global data.
        # All the rest of simulated agents should be not initialized but created.
        #
        agent = fwglobals.g.create_agent()
        self.started = True
        if reconnect:
            devices_info = self.db.fetch('devices_info', [])

            for device_info in devices_info:
                pid = device_info['created_by_process']
                start_time = device_info['process_created_time']
                if not self.is_process_alive(pid, start_time):
                    t = threading.Thread(
                            target=self.device_thread,
                            name='Simulate Device Thread',
                            args=(None, device_info['machine_id'], device_info['device_token'], True))
                    self.simulate_threads.append(t)
                    t.start()
            if not self.simulate_threads:
                self.log.info("No simulate devices are registered to reconnect")
                fwglobals.g.destroy_agent()
                return  #if No thread started, close the reconnect
        else:
            for id in range(count):
                simulated_agent = agent if id == 0 else None
                machine_id = str(uuid.uuid1())

                t = threading.Thread(
                            target=self.device_thread,
                            name='Simulate Device Thread ' + str(id),
                            args=(simulated_agent, machine_id, "", False))
                self.simulate_threads.append(t)
                t.start()
                time.sleep(1)

        while self.started:
            time.sleep(1)


    def device_thread(self, simulated_agent, machine_id, device_token, is_reconnect):
        """Simulates device - constructs agent, if not provided yet and runs register & connect loop.
        """
        agent = simulated_agent if simulated_agent else fwagent.FwAgent(handle_signals=False)
        self.simulate_agents.append(agent)

        if not is_reconnect:
            registered, _, device_token = agent.register(machine_id)
            while not registered:
                retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
                self.log.info(f"agent {machine_id}: retry registration in {retry_sec} seconds")
                time.sleep(retry_sec)
                if not self.started:
                    return
                registered, _, device_token = agent.register(machine_id)

            self.log.info(f"agent {machine_id}: registered")
            # Update device information in the database
            device_info_list = self.db.fetch('devices_info', [])
            device_info_list.append({
                                    "machine_id": machine_id,
                                    "device_token": device_token,
                                    "created_by_process": os.getpid(),
                                    "process_created_time": self.get_process_time(os.getpid())
                                    })
            self.db.put('devices_info', device_info_list)
        else:
            # Update device information in the database on reconnect
            devices_info = self.db.fetch('devices_info', [])
            for device_info in devices_info:
                if device_info['machine_id'] == machine_id:
                    device_info.update({
                                        "created_by_process": os.getpid(),
                                        "process_created_time": self.get_process_time(os.getpid())
                                        })
                    self.db.put('devices_info', devices_info)

        while not agent.connect(machine_id, device_token)[0] and self.started:
            retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            self.log.info(f"agent {machine_id}: retry connection in {retry_sec} seconds")
            time.sleep(retry_sec)

        while agent.ws.is_connected():
            agent.receive(timeout=1)

    def is_process_alive(self, pid, start_time):
        """Check if the process with the given PID and start time is still running."""
        try:
            proc = psutil.Process(pid)
            return int(proc.create_time()) == start_time
        except psutil.NoSuchProcess:
            return False

    def get_process_time(self, pid):
        return int(psutil.Process(pid).create_time())

    def reset_devices_list(self):
        """Reset the device list in the database."""
        self.db.put('devices_info', [])
        time.sleep(1)
        self.log.info(f"{self.db} > database reset successfully")

    def update_stats(self):
        """Update fake statistics.

        :returns: None.
        """
        if not self.started:
            return

        self.simulate_stats['tx_pkts'] += 10
        self.simulate_stats['tx_bytes'] += 1000
        self.simulate_stats['rx_bytes'] += 2000
        self.simulate_stats['rx_pkts'] += 20

        new_stats = {'ok': 1,
                     'message': {self.interface_wan: dict(self.simulate_stats),
                                 self.interface_lan: dict(self.simulate_stats)}}

        if new_stats['ok'] == 1:
            fwstats = fwglobals.g.statistics
            prev_stats = dict(fwstats.stats)  # copy of prev stats
            fwstats.stats['time'] = time.time()
            fwstats.stats['last'] = new_stats['message']
            fwstats.stats['ok'] = 1
            # Update info if previous stats valid
            if prev_stats['ok'] == 1:
                if_bytes = {}
                for intf, counts in list(fwstats.stats['last'].items()):
                    prev_stats_if = prev_stats['last'].get(intf, None)
                    if prev_stats_if != None:
                        rx_bytes = 1.0 * (counts['rx_bytes'] - prev_stats_if['rx_bytes'])
                        rx_pkts = 1.0 * (counts['rx_pkts'] - prev_stats_if['rx_pkts'])
                        tx_bytes = 1.0 * (counts['tx_bytes'] - prev_stats_if['tx_bytes'])
                        tx_pkts = 1.0 * (counts['tx_pkts'] - prev_stats_if['tx_pkts'])
                        if_bytes[intf] = {
                            'rx_bytes': rx_bytes,
                            'rx_pkts': rx_pkts,
                            'tx_bytes': tx_bytes,
                            'tx_pkts': tx_pkts
                        }

                fwstats.stats['bytes'] = if_bytes
                fwstats.stats['tunnel_stats'] = self.simulate_tunnel_stats
                fwstats.stats['period'] = fwstats.stats['time'] - prev_stats['time']
                fwstats.stats['running'] = True
        else:
            fwstats.stats['ok'] = 0

        # Add the update to the list of updates. If the list is full,
        # remove the oldest update before pushing the new one
        if len(fwstats.updates_list) is UPDATE_LIST_MAX_SIZE:
            fwstats.updates_list.pop(0)

        fwstats.updates_list.append({
            'ok': fwstats.stats['ok'],
            'running': fwstats.stats['running'],
            'stats': fwstats.stats['bytes'],
            'period': fwstats.stats['period'],
            'tunnel_stats': fwstats.stats['tunnel_stats'],
            'utc': time.time()
        })

def simulate(count, reconnect, delete):
    fwglobals.g.loadsimulator = LoadSimulator()
    if delete:
        fwglobals.g.loadsimulator.reset_devices_list()
        return
    fwglobals.g.cfg.debug['agent']['requests']['ignored'].append("sync-device")
    fwglobals.g.loadsimulator.start(count, reconnect)
    # Press CTRL-C to stop the simulation

