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
const cidr = require('cidr-tools');

async function up () {
  try {
    // Add the metric field to all interfaces
    // try to identify WAN interface with the default router
    // set metric 0 to that WAN interface and 100 to other WANs
    const devDocuments = await devices.find({});
    for (const deviceDoc of devDocuments) {
      const { _id, interfaces, defaultRoute } = deviceDoc;
      let defaultGwIfc;
      if (defaultRoute) {
        let defaultWanIfcs = interfaces.filter(i => i.gateway === defaultRoute);
        if (defaultWanIfcs.length > 1) {
          const defaultGwSubnet = `${defaultRoute}/32`;
          defaultWanIfcs = defaultWanIfcs.filter(i =>
            cidr.overlap(`${i.IPv4}/${i.IPv4Mask}`, defaultGwSubnet));
          if (defaultWanIfcs.length > 0) {
            defaultGwIfc = defaultWanIfcs[0];
          }
        } else if (defaultWanIfcs.length === 1) {
          defaultGwIfc = defaultWanIfcs[0];
        }
      }
      let autoAssignedMetric = 100;
      interfaces.forEach(ifc => {
        if (ifc.type === 'WAN' && ifc.gateway) {
          if (!defaultGwIfc) {
            defaultGwIfc = ifc;
            ifc.metric = '0';
          } else if (defaultGwIfc._id === ifc._id) {
            ifc.metric = '0';
          } else {
            ifc.metric = (autoAssignedMetric++).toString();
          }
        } else {
          ifc.metric = '';
        }
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
    // Remove the metric field from all devices
    await devices.updateMany(
      {},
      { $unset: { 'interfaces.$[].metric': '' } },
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
