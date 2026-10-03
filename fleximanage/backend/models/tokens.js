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

/**
 * Token Database Schema
 */
const tokenSchema = new Schema({
  // Organization
  org: {
    type: Schema.Types.ObjectId,
    ref: 'organizations',
    required: true
  },
  // description
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
  }
}, {
  timestamps: true
});

// indexing
tokenSchema.index({ name: 1, org: 1 }, { unique: true });

// Default exports
module.exports = mongoConns.getMainDB().model('tokens', tokenSchema);
