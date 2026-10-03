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
const AccessTokens = require('../models/accesstokens');
const logger = require('../logging/logging')({
  module: module.filename,
  type: 'migration'
});

async function up () {
  // Add group, to and role to access token
  try {
    await AccessTokens.updateMany(
      { to: { $exists: false } },
      { $set: { group: '', to: 'account', role: 'owner' } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: {
        collections: ['accessToken'],
        operation: 'up',
        err: err.message
      }
    });
    throw err;
  }
}

/**
 * No changes for down, we can keep the new fields
 */
async function down () {
}

module.exports = { up, down };
