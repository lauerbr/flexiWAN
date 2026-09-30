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

const { devices } = require('../models/devices');
const logger = require('../logging/logging')({ module: module.filename, type: 'migration' });
async function up () {
  // Set bandwidth to 100 if it is empty
  try {
    for (const bandwidth of ['bandwidthMbps.tx', 'bandwidthMbps.rx']) {
      await devices.updateMany(
        {
          interfaces: {
            $elemMatch: {
              type: 'WAN',
              $or: [
                { [bandwidth]: { $exists: false } },
                { [bandwidth]: 0 }
              ]
            }
          }
        },
        { $set: { ['interfaces.$[ifc].' + bandwidth]: 100 } },
        {
          arrayFilters: [
            {
              'ifc.type': 'WAN',
              $or: [
                { ['ifc.' + bandwidth]: { $exists: false } },
                { ['ifc.' + bandwidth]: 0 }
              ]
            }
          ],
          upsert: false
        }
      );
    }
    logger.info('Database migration done!', {
      params: { collections: ['devices'], operation: 'up' }
    });
  } catch (err) {
    logger.error('Database migration failed', {
      params: { collections: ['devices'], operation: 'up', err: err.message }
    });
  }
}

/**
 * Make any changes that UNDO the up function side effects here (if possible)
 */
async function down () {

}

module.exports = { up, down };
