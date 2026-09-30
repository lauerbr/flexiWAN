// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019  flexiWAN Ltd.

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
const { devices } = require('../models/devices');
const logger = require('../logging/logging')({ module: module.filename, type: 'migration' });

async function up () {
  try {
    // Add the gateway field to all devices
    // LAN interfaces: add the an empty field
    // WAN interfaces: set to the device's default gateway
    const devDocuments = await devices.find({});
    for (const deviceDoc of devDocuments) {
      const { _id, interfaces } = deviceDoc;
      interfaces.forEach(ifc => {
        ifc.gateway = ifc.type === 'WAN' ? deviceDoc.defaultRoute : '';
      });
      await devices.update(
        { _id: _id },
        { $set: { interfaces: interfaces } },
        { upsert: false }
      );
    }
  } catch (err) {
    logger.error('Database migration failed', {
      params: { collections: ['devices'], operation: 'up', err: err.message }
    });
  }
}

async function down () {
  try {
    // Remove the WAN gateway from all devices
    await devices.updateMany(
      {},
      { $unset: { 'interfaces.$[].gateway': '' } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: {
        collections: ['devices'],
        operation: 'down',
        err: err.message
      }
    });
  }
}

module.exports = { up, down };
