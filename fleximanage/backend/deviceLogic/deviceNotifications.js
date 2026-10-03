// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019-2021  flexiWAN Ltd.

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
const notificationsConf = require('../models/notificationsConf');
const { devices } = require('../models/devices');
const deviceQueues = require('../utils/deviceQueue')(
  configs.get('kuePrefix'),
  configs.get('redisUrl')
);
const logger = require('../logging/logging')({ module: module.filename, type: 'job' });
const deviceNotificationTypes = new Set([
  'Device memory usage',
  'Hard drive usage',
  'Link/Tunnel round trip time',
  'Link/Tunnel default drop rate',
  'Temperature'
]);
const { getMajorVersion, getMinorVersion } = require('../versioning');
const { transformNotificationsSettings } = require('../deviceLogic/jobParameters');

/**
 * Creates and queues the add-notifications-config job.
 * @async
 * @param  {Array}    devicesList    an array of the devices to be modified (array of ids)
 * @param  {Object}   user      User object
 * @param  {Object}   data      Additional data used by caller includes the orgId and the rules
 * @param  {Object}   org       The organization Id
 * @param  {Object}   rules     object in which: keys= notification name, values = settings
 * @return {None}
 */

const isCustomNotificationsSupported = (device) => {
  const majorVersion = getMajorVersion(device.versions.agent);
  const minorVersion = getMinorVersion(device.versions.agent);
  return (majorVersion > 6 || (majorVersion === 6 && minorVersion >= 3));
};

const apply = async (devicesList, user, data) => {
  const { org: orgId, rules } = data;
  const filteredRules = transformNotificationsSettings(rules, deviceNotificationTypes);

  const opDevices = await Promise.all(
    devicesList.map(d => d.populate('policies.firewall.policy', '_id name rules')
      .populate('interfaces.pathlabels', '_id name description color type')
      .execPopulate()
    ));
  const errors = [];
  const applyPromises = [];
  const tasks = [{
    entity: 'agent',
    message: 'add-notifications-config',
    params: { org: orgId, rules: filteredRules }
  }];
  for (const device of opDevices) {
    const supportNotifications = isCustomNotificationsSupported(device);
    if (!supportNotifications) {
      errors.push({
        valid: false,
        err: `The device ${device.hostname}'s current version doesn't support custom notifications`
      });
    } else {
      const { machineId } = device;
      logger.info('Set device notifications:', { params: { machineId, user, data } });

      applyPromises.push(deviceQueues
        .addJob(
          machineId,
          user.username,
          orgId,
          // Data
          { title: 'Setting notifications for device: ' + device.hostname, tasks: tasks },
          // Response data
          {
            method: 'notifications',
            data: {
              device: device._id,
              org: orgId
            }
          },
          // Metadata
          { priority: 'normal', attempts: 1, removeOnComplete: false },
          // Complete callback
          null
        )
      );
    }
  }
  const promisesStatus = await Promise.allSettled(applyPromises);
  const { fulfilled, reasons } = promisesStatus.reduce(({ fulfilled, reasons }, elem) => {
    if (elem.status === 'fulfilled') {
      const job = elem.value;
      fulfilled.push(job.id);
    } else {
      if (!reasons.includes(elem.reason.message)) {
        reasons.push(elem.reason.message);
      }
    };
    return { fulfilled, reasons };
  }, { fulfilled: [], reasons: errors });
  const status = fulfilled.length < opDevices.length
    ? 'partially completed' : 'completed';
  const message = fulfilled.length < opDevices.length
    ? `Warning: ${fulfilled.length} of ${opDevices.length} Set device's notifications job added.` +
        ` Some devices have following errors: ${reasons.join('. ')}`
    : `Set device's notifications${opDevices.length > 1 ? 's' : ''} added successfully`;
  return { ids: fulfilled, status, message };
};

const sync = async (deviceId) => {
  const device = await devices.findOne(
    { _id: deviceId }
  );
  let callComplete = false;
  const completeCbData = [];
  const request = [];
  if (device) {
    const supportNotifications = isCustomNotificationsSupported(device);
    if (supportNotifications) {
      const orgId = device.org;
      const getOrgNotificationsConfig = await notificationsConf.findOne({ org: orgId.toString() });
      const orgNotificationsConfig = getOrgNotificationsConfig.rules;
      const filteredRules = transformNotificationsSettings(
        orgNotificationsConfig,
        deviceNotificationTypes
      );
      request.push({
        entity: 'agent',
        message: 'add-notifications-config',
        params: { org: orgId, rules: filteredRules }
      });
      completeCbData.push({ orgId, deviceId, op: 'notifications' });
      callComplete = true;
    }
  }
  return {
    requests: request,
    completeCbData,
    callComplete
  };
};

module.exports = {
  apply: apply,
  sync: sync
};
