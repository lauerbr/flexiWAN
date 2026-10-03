// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2023  flexiWAN Ltd.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const configs = require('../configs')();
const deviceStatus = require('../periodic/deviceStatus')();
const deviceQueues = require('../utils/deviceQueue')(
  configs.get('kuePrefix'),
  configs.get('redisUrl')
);
const logger = require('../logging/logging')({ module: module.filename, type: 'job' });
const { differenceWith, isEqual, keyBy } = require('lodash');
const { transformVrrp, transformDHCP } = require('./jobParameters');
const Vrrp = require('../models/vrrp');
const { getMajorVersion, getMinorVersion } = require('../versioning');

/**
 * Creates and queues the add/remove job.
 * @async
 * @param  {object} origVrrpGroup   object with VRRP group before the modification
 * @param  {object} newVrrpGroup    object with VRRP group after the modification
 * @param  {string} org             organization ID
 * @param  {object} user            user object
 * @return {None}
 */
const queue = async (origVrrpGroup, newVrrpGroup, orgId, user) => {
  const { username } = user;
  const applyPromises = [];
  const devicesTasks = {};

  const _addTasks = (vrrpGroupDevice, key, vrrpGroup) => {
    const deviceId = vrrpGroupDevice.device._id.toString();

    if (!(deviceId in devicesTasks)) {
      devicesTasks[deviceId] = {
        orig: [],
        updated: [],
        tasks: [],
        origDeviceObj: key === 'orig' ? vrrpGroupDevice.device : null,
        updatedDeviceObj: key === 'updated' ? vrrpGroupDevice.device : null,
        op: null,
        origDhcp: {},
        updatedDhcp: {},
        newVrrpGroup: null,
        origVrrpGroup: null
      };
    }

    if (key === 'updated') {
      devicesTasks[deviceId].newVrrpGroup = vrrpGroup;
    }
    if (key === 'orig') {
      devicesTasks[deviceId].origVrrpGroup = vrrpGroup;
    }

    devicesTasks[deviceId][key].push(transformVrrp(vrrpGroupDevice, vrrpGroup));

    const dhcpKey = `${key}Dhcp`;
    devicesTasks[deviceId][dhcpKey] = keyBy(vrrpGroupDevice.device.dhcp, 'interface');
  };

  for (const vrrpGroupDevice of origVrrpGroup?.devices ?? []) {
    _addTasks(vrrpGroupDevice, 'orig', origVrrpGroup);
  }

  for (const vrrpGroupDevice of newVrrpGroup?.devices ?? []) {
    _addTasks(vrrpGroupDevice, 'updated', newVrrpGroup);
  }

  for (const deviceId in devicesTasks) {
    const newVrrpGroup = devicesTasks[deviceId].newVrrpGroup;
    const origVrrpGroup = devicesTasks[deviceId].origVrrpGroup;
    const [addDevice, removeDevice] = [
      differenceWith(
        devicesTasks[deviceId].updated,
        devicesTasks[deviceId].orig,
        (updated, orig) => {
          return isEqual(updated, orig);
        }),
      differenceWith(
        devicesTasks[deviceId].orig,
        devicesTasks[deviceId].updated,
        (orig, updated) => {
          return isEqual(orig, updated);
        })
    ];

    if (removeDevice.length > 0) {
      devicesTasks[deviceId].tasks.push(...removeDevice.map(d => {
        return {
          entity: 'agent',
          message: 'remove-vrrp-group',
          params: d
        };
      }));
      devicesTasks[deviceId].op = 'remove';
    }

    if (addDevice.length > 0) {
      devicesTasks[deviceId].tasks.push(...addDevice.map(d => {
        return {
          entity: 'agent',
          message: 'add-vrrp-group',
          params: d
        };
      }));
      devicesTasks[deviceId].op = 'create';
    }

    // handle changes in DHCP
    const origDhcp = devicesTasks[deviceId].origDhcp;
    const updatedDhcp = devicesTasks[deviceId].updatedDhcp;

    for (const dhcpInterface in origDhcp) {
      // device now removed - if there is dhcp, need to recreate with lan ip
      if (!(dhcpInterface in updatedDhcp)) {
        devicesTasks[deviceId].tasks.push({
          entity: 'agent',
          message: 'remove-dhcp-config',
          params: transformDHCP(origDhcp[dhcpInterface], deviceId, [origVrrpGroup])
        });
        devicesTasks[deviceId].tasks.push({
          entity: 'agent',
          message: 'add-dhcp-config',
          params: transformDHCP(origDhcp[dhcpInterface], deviceId, [])
        });
        continue;
      }
    }

    for (const dhcpInterface in updatedDhcp) {
      // device now added - if there is dhcp, need to recreate with vrrp gateway
      if (!(dhcpInterface in origDhcp)) {
        devicesTasks[deviceId].tasks.push({
          entity: 'agent',
          message: 'remove-dhcp-config',
          params: transformDHCP(updatedDhcp[dhcpInterface], deviceId, [])
        });
        devicesTasks[deviceId].tasks.push({
          entity: 'agent',
          message: 'add-dhcp-config',
          params: transformDHCP(
            updatedDhcp[dhcpInterface],
            deviceId,
            newVrrpGroup ? [newVrrpGroup] : []
          )
        });
        continue;
      }
    }

    // check modification
    const origTransformed = Object.values(devicesTasks[deviceId].updatedDhcp).map(dhcp => {
      return transformDHCP(dhcp, deviceId, origVrrpGroup ? [origVrrpGroup] : null);
    });
    const updatedTransformed = Object.values(devicesTasks[deviceId].origDhcp).map(dhcp => {
      return transformDHCP(dhcp, deviceId, newVrrpGroup ? [newVrrpGroup] : []);
    });
    const [addDhcpDevice, removeDhcpDevice] = [
      differenceWith(
        updatedTransformed,
        origTransformed,
        (updated, orig) => {
          return isEqual(updated, orig);
        }),
      differenceWith(
        origTransformed,
        updatedTransformed,
        (orig, updated) => {
          return isEqual(orig, updated);
        })
    ];
    if (removeDhcpDevice.length === addDhcpDevice.length) {
      if (removeDhcpDevice.length > 0) {
        devicesTasks[deviceId].tasks.push(...removeDhcpDevice.map(d => {
          return {
            entity: 'agent',
            message: 'remove-dhcp-config',
            params: d
          };
        }));
      }

      if (addDhcpDevice.length > 0) {
        devicesTasks[deviceId].tasks.push(...addDhcpDevice.map(d => {
          return {
            entity: 'agent',
            message: 'add-dhcp-config',
            params: d
          };
        }));
      }
    }
  }

  for (const deviceId in devicesTasks) {
    if (devicesTasks[deviceId].tasks.length === 0) {
      continue;
    }

    const device = devicesTasks[deviceId].origDeviceObj || devicesTasks[deviceId].updatedDeviceObj;
    const { machineId, name, _id } = device;

    // Set the device state to "pending". Device state will
    // be updated again when the device sends periodic message
    await deviceStatus.setDeviceState(machineId, 'pending');

    const vrrpGroup = newVrrpGroup || origVrrpGroup;
    await Vrrp.updateOne(
      { org: orgId, _id: vrrpGroup._id },
      { $set: { 'devices.$[elem].jobStatus': 'pending' } },
      { arrayFilters: [{ 'elem.device': _id }] }
    );

    let tasks = devicesTasks[deviceId].tasks;
    if (tasks.length > 0) {
      tasks = [{
        entity: 'agent',
        message: 'aggregated',
        params: { requests: tasks }
      }];
    }

    applyPromises.push(deviceQueues.addJob(
      machineId,
      username,
      orgId,
      // Data
      {
        title: 'Modify VRRP for device ' + name,
        tasks: tasks
      },
      // Response data
      {
        method: 'vrrp',
        data: {
          device: _id,
          vrrpGroup: newVrrpGroup,
          op: devicesTasks[deviceId].op, // "remove" or "create"
          orgId,
          machineId
        }
      },
      // Metadata
      { priority: 'normal', attempts: 1, removeOnComplete: false },
      // Complete callback
      null
    ));
  }

  const promisesStatus = await Promise.allSettled(applyPromises);
  const { fulfilled, reasons } = promisesStatus.reduce(({ fulfilled, reasons }, elem) => {
    if (elem.status === 'fulfilled') {
      const job = elem.value;
      logger.info('VRRP device job queued', {
        params: {
          jobId: job.id,
          machineId: job.type
        }
      });
      fulfilled.push(job.id);
    } else {
      if (!reasons.includes(elem.reason.message)) {
        reasons.push(elem.reason.message);
      }
    };
    return { fulfilled, reasons };
  }, { fulfilled: [], reasons: [] });
  return { ids: fulfilled, reasons };
};

/**
 * Called when VRRP job completed
 * @param  {number} jobId Kue job ID number
 * @param  {Object} res   device object ID and organization
 * @return {void}
 */
const complete = async (jobId, res) => {
  const { device: deviceId = null, orgId, vrrpGroup, op, machineId } = res;

  if (!deviceId) {
    logger.warn('VRRP Job completed without deviceId', {
      params: { orgId, vrrpGroupId: vrrpGroup?._id, op, jobId: jobId }
    });
    return;
  }

  logger.info('VRRP job complete', {
    params: { deviceId, orgId, vrrpGroupId: vrrpGroup?._id, op, jobId: jobId }
  });

  if (op === 'create') { // for "remove" device is not exists so nothing to update
    await Vrrp.updateOne(
      { org: orgId, _id: vrrpGroup._id },
      { $set: { 'devices.$[elem].jobStatus': 'installed' } },
      { arrayFilters: [{ 'elem.device': deviceId }] }
    );
  }

  if (op === 'remove') {
    // clear vrrp status from memory for this device
    deviceStatus.clearDeviceVrrpStatus(machineId);
  }
};

/**
 * Called when VRRP job failed
 * @param  {number} jobId Kue job ID number
 * @param  {Object} res   device object ID and organization
 * @return {void}
 */
const error = async (jobId, res) => {
  logger.error('VRRP job failed', {
    params: { result: res, jobId: jobId }
  });

  const { device: deviceId, orgId, vrrpGroup, op } = res;

  if (op === 'create') { // for "remove" device is not exists so nothing to update
    await Vrrp.updateOne(
      { org: orgId, _id: vrrpGroup._id },
      { $set: { 'devices.$[elem].jobStatus': 'failed' } },
      { arrayFilters: [{ 'elem.device': deviceId }] }
    );
  }
};

/**
 * Creates the vrrp section in the full sync job.
 * @return Object
 */
const sync = async (deviceId, org) => {
  const vrrpGroups = await Vrrp.find(
    { org: org, 'devices.device': deviceId }
  ).populate('devices.device').lean();

  const request = [];
  const completeCbData = [];
  let callComplete = false;
  for (const vrrpGroup of vrrpGroups) {
    for (const vrrpGroupDevice of vrrpGroup.devices) {
      // Send vrrp job for the device that is should be synced only.
      // Hence, filter out other devices in the vrrp group.
      if (vrrpGroupDevice.device._id.toString() !== deviceId.toString()) {
        continue;
      }

      const majorVersion = getMajorVersion(vrrpGroupDevice.device.versions.device);
      const minorVersion = getMinorVersion(vrrpGroupDevice.device.versions.device);
      if (majorVersion < 6 || (majorVersion === 6 && minorVersion <= 2)) {
        continue;
      }

      const params = transformVrrp(vrrpGroupDevice, vrrpGroup);
      request.push({
        entity: 'agent',
        message: 'add-vrrp-group',
        params
      });

      completeCbData.push({
        device: vrrpGroupDevice.device._id.toString(),
        orgId: org,
        op: 'create',
        vrrpGroup
      });

      callComplete = true;
    }
  }

  return {
    requests: request,
    completeCbData,
    callComplete
  };
};

/**
 * Complete handler for sync job
 * @return void
 */
const completeSync = async (jobId, jobsData) => {
  try {
    for (const data of jobsData) {
      await complete(jobId, data);
    }
  } catch (err) {
    logger.error('VRRP sync complete callback failed', {
      params: { jobsData, reason: err.message }
    });
  }
};

/**
 * Called if VRRP job was removed
 * @async
 * @param  {number} jobId Kue job ID
 * @param  {Object} res
 * @return {void}
 */
const remove = async (job) => {
  if (['inactive', 'delayed', 'active'].includes(job._state)) {
    logger.info('VRRP job removed', { params: { jobId: job.id } });

    const { device: deviceId, orgId, vrrpGroup, op } = job.data.response.data;
    if (op === 'create') { // for "remove" device is not exists so nothing to update
      await Vrrp.updateOne(
        { org: orgId, _id: vrrpGroup._id },
        { $set: { 'devices.$[elem].jobStatus': 'removed' } },
        { arrayFilters: [{ 'elem.device': deviceId }] }
      );
    }
  }
};

module.exports = {
  queue,
  sync,
  complete,
  error,
  remove,
  completeSync
};
