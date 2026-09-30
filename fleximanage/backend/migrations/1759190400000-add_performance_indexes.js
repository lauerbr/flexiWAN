// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2025  flexiWAN Ltd.

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

// Create the indexes used by the periodic tasks and the heavy API queries.
// The same indexes are defined in the schemas, so they are also built when
// mongoose autoIndex is enabled. Building them here allows deployments to
// run with mongoAutoIndex=false.
const { deviceStats } = require('../models/analytics/deviceStats');
const applicationStats = require('../models/analytics/applicationStats');
const { devices } = require('../models/devices');
const tunnels = require('../models/tunnels');
const notifications = require('../models/notifications');
const logger = require('../logging/logging')({ module: module.filename, type: 'migration' });

const newIndexes = [
  { model: deviceStats, key: { org: 1, device: 1, time: 1 } },
  { model: applicationStats, key: { org: 1, device: 1, app: 1, time: 1 } },
  { model: devices, key: { isConnected: 1 } },
  { model: tunnels, key: { deviceA: 1 } },
  { model: tunnels, key: { deviceB: 1 } },
  {
    model: tunnels,
    key: { isPending: 1 },
    options: { partialFilterExpression: { isPending: true } }
  },
  { model: notifications, key: { 'targets.deviceId': 1 } }
];

// Indexes that are a prefix of { org: 1, resolved: 1, eventType: 1 }
const redundantIndexes = [
  { model: notifications, key: { org: 1 } },
  { model: notifications, key: { org: 1, resolved: 1 } }
];

const indexName = (key) => Object.entries(key).map(([k, v]) => `${k}_${v}`).join('_');

const dropIfExists = async ({ model, key }) => {
  try {
    await model.collection.dropIndex(indexName(key));
  } catch (err) {
    // IndexNotFound
    if (err.code !== 27) throw err;
  }
};

async function up () {
  try {
    for (const { model, key, options } of newIndexes) {
      await model.collection.createIndex(key, { background: true, ...options });
    }
    for (const idx of redundantIndexes) {
      await dropIfExists(idx);
    }
  } catch (err) {
    logger.error('Database migration failed', {
      params: {
        collections: ['deviceStats', 'applicationStats', 'devices', 'tunnels', 'notifications'],
        operation: 'up',
        err: err.message
      }
    });
    throw err;
  }
}

async function down () {
  try {
    for (const { model, key } of redundantIndexes) {
      await model.collection.createIndex(key, { background: true });
    }
    for (const idx of newIndexes) {
      await dropIfExists(idx);
    }
  } catch (err) {
    logger.error('Database migration failed', {
      params: {
        collections: ['deviceStats', 'applicationStats', 'devices', 'tunnels', 'notifications'],
        operation: 'down',
        err: err.message
      }
    });
    throw err;
  }
}

module.exports = { up, down };
