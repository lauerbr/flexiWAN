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

const { membership } = require('../models/membership');
const { devices } = require('../models/devices');
const { addPerms, removePerms } = require('./utils/updatePerms');
const logger = require('../logging/logging')({
  module: module.filename,
  type: 'migration'
});

async function up () {
  // Add vrrp to user permission
  try {
    await addPerms(membership, 'vrrp');

    await devices.updateMany(
      { },
      { $set: { 'dhcp.$[].options': [] } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: {
        collections: ['vrrp'],
        operation: 'up',
        err: err.message
      }
    });
    throw err;
  }
}

async function down () {
  try {
    // Remove vrrp permissions
    await removePerms(membership, 'vrrp');

    await devices.updateMany(
      { },
      { $unset: { 'dhcp.$[].options': '' } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: {
        collections: ['vrrp'],
        operation: 'down',
        err: err.message
      }
    });
    throw err;
  }
}

module.exports = { up, down };
