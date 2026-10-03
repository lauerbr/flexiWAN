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

import threading
import time
import operator
import fwglobals
import fwutils

class FwNatSessionsCache:
    """
    Holds NAT sessions data along with supporting metadata.

    Attributes:
      - sessions: List of NAT session entries.
      - indexes: Dictionary of indexes for fast filtering.
      - last_update_time: Timestamp of the last cache update.
      - lock: Lock used only to prevent cleanup during a query.
    """
    def __init__(self):
        self.sessions = None
        self.indexes = None
        self.last_update_time = None
        self.lock = threading.Lock()

class FwNatSessionsManager:
    """
    Manages the NAT sessions cache.

    Responsibilities:
      - Load session data from the VPP API.
      - Build indexes for quick filtering.
      - Provide access to session data.
      - Automatically clear (invalidate) the cache after a timeout.

    Note:
      Only one thread accesses this class. The lock is used only to ensure that the
      timer-based cleanup does not clear data while a query is executing.

    Args:
      cache_timeout (int): Cache lifetime in seconds.
    """
    def __init__(self, cache_timeout=120):
        self.cache = FwNatSessionsCache()
        self.cache_timeout = cache_timeout
        self.timer_timeout = cache_timeout * 2
        self.cleanup_timer = None

        # Order of keys for filtering and aggregation.
        self.order = [
            "sw_if_index",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "translated_source_ip",
            "translated_source_port",
            "translated_destination_ip",
            "translated_destination_port",
            "nat_type",
            "packets",
            "interface_type",
        ]

    def convert_to_int_if_numeric(self, value):
        try:
            return int(value)
        except (ValueError, TypeError):
            return value

    def _load_data(self):
        """
        Performs heavy data loading and processing outside any lock.

        Returns:
          A tuple (final_data, indexes, current_time).

        Notes:
          - The function fetches data from the VPP API and builds a list of session dictionaries.
          - It also builds indexes for filtering based on keys from self.order.
          - 'dev_id' is obtained from sw_if_index using dev_id_cache.
            For LAN NAT, a sw_if_index of 4294967295 may result in dev_id being None.
        """
        data = fwglobals.g.router_api.vpp_api.vpp.call('nat44_user_session_dump')

        # Prepare indexes for filtering.
        indexes = { key: {} for key in self.order }
        dev_id_cache = fwglobals.g.db.get('router_api', {}).get('sw_if_index_to_dev_id', {})
        dev_id_type_cache = { ifc['dev_id']: ifc['type'] for ifc in fwglobals.g.router_cfg.get_interfaces() }
        proto_name_by_bpp_num = { v: k for k, v in fwutils.proto_map.items() }

        final_data = []
        for idx, entry in enumerate(data):
            dev_id = dev_id_cache.get(entry.sw_if_index)  # For LAN NAT, may return None.
            nat_entry = {
                'source_ip': entry.inside_ip_address.compressed,
                'source_port': entry.inside_port,
                'translated_source_ip': entry.outside_ip_address.compressed,
                'translated_source_port': entry.outside_port,
                'destination_ip': entry.ext_host_address.compressed,
                'destination_port': entry.ext_host_port,
                'translated_destination_ip': entry.ext_host_nat_address.compressed if entry.ext_host_nat_port else None,
                'translated_destination_port': entry.ext_host_nat_port,
                'sw_if_index': dev_id,
                'protocol': proto_name_by_bpp_num[entry.protocol],
                'packets': entry.total_pkts,
                # Static Session = (entry.flags & 0x1 == True)
                # LAN NAT 1to1 = (entry.flags & 0x200 == True)
                'nat_type': 'static' if (entry.flags & 0x1 == True) or (entry.flags & 0x200 == True) else 'dynamic',
                'interface_type': dev_id_type_cache.get(dev_id),
            }

            for key, value in nat_entry.items():
                if value not in indexes[key]:
                    indexes[key][value] = set()
                indexes[key][value].add(idx)
            final_data.append(nat_entry)

        self.cache.sessions = final_data
        self.cache.indexes = indexes
        self.cache.last_update_time = time.time()

    def _schedule_cleanup(self):
        """
        Schedules a cleanup task to invalidate the cache after self.cleanup_timer seconds.
        """
        if self.cleanup_timer:
            # When cancel() is called on a Timer, it only prevents the Timer function from running if
            # it hasn't already started. If the Timer function has already begun execution and is waiting
            # for a lock, then cancel() will not stop it from running.
            # To handle this, _clear_memory_data includes its own protection by checking if the cache is still valid,
            # ensuring that newly loaded data is not accidentally cleared.
            self.cleanup_timer.cancel()
            self.cleanup_timer = None

        self.cleanup_timer = threading.Timer(self.timer_timeout, self._clear_memory_data)
        self.cleanup_timer.start()


    def _clear_memory_data(self):
        """
        Clears the cache if needed.

        When new data is loaded, a new Timer is created to clear the cache after self.cleanup_timer (4 minutes).
        However, the data itself is considered valid for self.cache_timeout (2 minutes). This means that if new data is
        loaded (for example, at minute 3), a new timer is started (set for minute 8). In such a case,
        the first timer (scheduled to run at minute 4) should not clear the new data. The check
        using _is_cache_valid() ensures that we do not clear the cache if the data is still valid
        (i.e., if new data was loaded recently), thus preventing accidental removal of updated data.
        """
        with self.cache.lock:
            # If the cache is still valid, do not clear it. This protects newly loaded data
            # from being cleared by an older timer.
            if self._is_cache_valid():
                return
            self.cache.sessions = None
            self.cache.indexes = None
            self.cache.last_update_time = None
            self.cleanup_timer = None

    def _is_cache_valid(self):
        """
        Checks whether the cached data is still valid.

        Returns:
        True if the cache exists and has been updated within cache_timeout seconds.
        """
        return (
            self.cache.last_update_time is not None and
            time.time() - self.cache.last_update_time <= self.cache_timeout
        )

    def get_sessions(self, pagination=None, depth=None, filters=None, sort=None, refresh=False):
        """
        Retrieves NAT sessions with optional filtering, sorting, pagination, and aggregation.
        The lock is held during the entire processing to ensure that the cleanup timer does not
        remove the sessions while a query is executing.

        Parameters:
        - pagination (dict): Contains 'offset' and 'limit' keys for slicing the results.
        - depth (int): If provided, aggregates sessions by the first 'depth' keys (from self.order)
                    and sums their 'packets'. This reduces redundancy when many sessions share
                    the same key values.
        - filters (dict): Key-value pairs used to filter sessions.
        - sort (dict): Contains 'field' and 'order' keys to sort the results.
        - refresh (bool): Forces a cache refresh if set to True.

        Returns:
        A dictionary with:
            - total: The total number of matching sessions.
            - entries: The list of session entries after processing.
            - last_update_time: The timestamp when the cache was last updated.
    """
        def _handle_return(_entries, last_update_time):
            total = len(_entries)

            # Sort entries before applying pagination if a sort configuration is provided.
            if sort:
                sort_by_field = sort.get('field')
                sort_by_order = sort.get('order')
                if sort_by_field and sort_by_order:
                    _entries = sorted(
                        _entries,
                        key=lambda x: x[sort_by_field],
                        reverse=(sort_by_order.lower() == "descending")
                    )

            # Apply pagination by slicing the entries based on offset and limit.
            if pagination:
                offset, limit = pagination['offset'], pagination['limit']
                _entries = _entries[offset:(offset + limit)]

            if depth:
                # When depth is specified (e.g., depth=1 with key "sw_if_index"):
                # - Instead of returning many identical entries for the same key, we aggregate them.
                # - For example, 100,000 entries sharing the same "sw_if_index" will be aggregated
                #   into one entry with a summed 'packets' count.
                #
                # This minimizes redundancy while preserving the overall aggregated information.

                # Retain only the first 'depth' keys from the session data.
                keys_to_keep = self.order[:depth]

                # Use a dictionary to accumulate packet counts for each unique combination of keys.
                aggregated = {}
                for obj in _entries:
                    # Create a tuple from the selected keys to serve as the grouping key.
                    key = tuple(obj[k] for k in keys_to_keep)
                    aggregated[key] = aggregated.get(key, 0) + obj['packets']

                # Convert the aggregated data back into a list of dictionaries.
                _entries = [
                    {**dict(zip(keys_to_keep, key)), 'packets': total_packets}
                    for key, total_packets in aggregated.items()
                ]

            return {
                'total': total,
                'entries': _entries,
                'last_update_time': last_update_time,
            }

        # Acquire the lock to protect the entire process of building data and updating the shared cache.
        # This ensures:
        # 1. The cleanup timer does not run while data is being constructed.
        # 2. Data building does not occur concurrently with a cleanup.
        # 3. Cleanup does not occur during query execution (including filtering operations).
        # 4. Multiple threads do not trigger simultaneous heavy data rebuilds on expired sessions.
        with self.cache.lock:
            if not self.cache.sessions or not self._is_cache_valid() or refresh:
                self._load_data()
                self._schedule_cleanup()

            last_update_time = self.cache.last_update_time

            # If no filters are provided, return a shallow copy of the complete session list.
            if not filters:
                return _handle_return(self.cache.sessions.copy(), last_update_time)

            selected_indexes = None
            # Process each filter by intersecting the index sets to identify matching sessions.
            for key, value in filters.items():
                value = self.convert_to_int_if_numeric(value)
                if key not in self.cache.indexes:
                    continue
                if value not in self.cache.indexes[key]:
                    self.cache.indexes[key][value] = set()
                if selected_indexes is None:
                    # Create a shallow copy for safe in-place intersection.
                    selected_indexes = self.cache.indexes[key][value].copy()
                else:
                    selected_indexes.intersection_update(self.cache.indexes[key][value])

            # If no indexes match the filters, return an empty result.
            if not selected_indexes:
                return _handle_return([], last_update_time)

            try:
                # Attempt to retrieve session entries using the selected indexes.
                getter = operator.itemgetter(*selected_indexes)
                selected_data = getter(self.cache.sessions)
            except TypeError:
                # Handle the case when only one index is found (itemgetter returns a single dict).
                selected_data = self.cache.sessions[list(selected_indexes)[0]]
            entries = [selected_data] if isinstance(selected_data, dict) else list(selected_data)

            return _handle_return(entries, last_update_time)
