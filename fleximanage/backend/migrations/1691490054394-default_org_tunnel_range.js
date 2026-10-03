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

const orgModel = require('../models/organizations');
const logger = require('../logging/logging')({ module: module.filename, type: 'migration' });

async function up () {
  try {
    await orgModel.updateMany(
      { tunnelRange: { $exists: false } },
      { $set: { tunnelRange: '10.100.0.0' } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: { collections: ['organizations'], operation: 'up', err: err.message }
    });
    throw err;
  }
}

async function down () {
  try {
    await orgModel.updateMany(
      { tunnelRange: { $exists: true } },
      { $unset: { tunnelRange: '' } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: { collections: ['organizations'], operation: 'down', err: err.message }
    });
    throw err;
  }
}

module.exports = { up, down };
