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
const accessTokens = require('../../models/accesstokens');

const addPerms = async (db, field) => {
  // Update memberships collection
  const cond = [{ role: 'owner' }, { role: 'manager' }];
  await db.updateMany(
    { $or: cond },
    { $set: { [`perms.${field}`]: 15 } },
    { upsert: false }
  );
  await db.updateMany(
    { $nor: cond },
    { $set: { [`perms.${field}`]: 1 } },
    { upsert: false }
  );

  // Update access tokens
  await accessTokens.updateMany(
    { permissions: { $exists: true } },
    { $set: { [`permissions.${field}`]: 15 } },
    { upsert: false }
  );
};

const removePerms = async (db, field) => {
  // Revert memberships collections
  await db.updateMany(
    {},
    { $unset: { [`perms.${field}`]: '' } },
    { upsert: false }
  );

  // Revert access token change
  await accessTokens.updateMany(
    { permissions: { $exists: true } },
    { $unset: { [`permissions.${field}`]: true } },
    { upsert: false }
  );
};

module.exports = {
  addPerms,
  removePerms
};
