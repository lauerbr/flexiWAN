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

const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const mongoConns = require('../mongoConns.js')();
const validators = require('./validators');
const { permissionsSchema } = require('./membership');

/**
 * Access Tokens Schema
 */
const accessTokenSchema = new Schema({
  // account
  account: {
    type: Schema.Types.ObjectId,
    ref: 'accounts',
    required: true
  },
  // group name
  group: {
    type: String,
    required: false,
    unique: false,
    maxlength: [50, 'Group length must be at most 50']
  },
  // organization
  organization: {
    type: Schema.Types.ObjectId,
    ref: 'organizations',
    required: false
  },
  // applied to
  to: {
    type: String,
    enum: ['account', 'organization', 'group'],
    required: true
  },
  // default roles are 'owner', 'manager', 'viewer'
  role: {
    type: String,
    enum: ['owner', 'manager', 'viewer'],
    required: true,
    unique: false,
    maxlength: [10, 'role length must be at most 10']
  },
  // access token description
  name: {
    type: String,
    required: true,
    validate: {
      validator: validators.validateTokenName,
      message: 'Token name format is invalid'
    }
  },
  // token itself
  token: {
    type: String,
    required: true,
    maxlength: [1024, 'Token length must be at most 1024']
  },
  // permissions associate with this token
  permissions: {
    type: permissionsSchema,
    required: false
  },
  // is valid. Reserved for future use
  isValid: {
    type: Boolean,
    required: true,
    default: true
  }
}, {
  timestamps: true
});

// indexing
accessTokenSchema.index({ name: 1, account: 1 }, { unique: true });

// default exports
module.exports = mongoConns.getMainDB().model('accesstokens', accessTokenSchema);
