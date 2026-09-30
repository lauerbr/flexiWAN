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

const peersModel = require('../models/peers');
const logger = require('../logging/logging')({ module: module.filename, type: 'migration' });

/**
 * Make any changes you need to make to the database here
 */
async function up () {
  try {
    await peersModel.updateMany(
      { ikeLifeTime: { $exists: false } },
      { $set: { ikeLifeTime: '86400', pfs: false } },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: { collections: ['peers'], operation: 'up', err: err.message }
    });
    throw new Error(err.message);
  }
}

/**
 * Make any changes that UNDO the up function side effects here (if possible)
 */
async function down () {
  try {
    await peersModel.updateMany(
      { },
      {
        $unset: { ikeLifeTime: '', pfs: '' }
      },
      { upsert: false }
    );
  } catch (err) {
    logger.error('Database migration failed', {
      params: { collections: ['peers'], operation: 'down', err: err.message }
    });
    throw new Error(err.message);
  }
}

module.exports = { up, down };
