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

const mongoose = require('mongoose');
const mongoConns = require('../mongoConns.js')();
const Schema = mongoose.Schema;
const { validateIPv4, validateDevId } = require('./validators.js');

// Define a getter on object ID that
// converts it to a string
Schema.ObjectId.get(v => v ? v.toString() : v);

const vrrpDeviceSchema = new Schema({
  device: {
    type: Schema.Types.ObjectId,
    ref: 'devices',
    required: true
  },
  interface: {
    type: String,
    validate: {
      validator: validateDevId,
      message: 'interface should be a valid interface devId'
    },
    required: true
  },
  priority: {
    type: Number,
    required: true,
    min: [1, 'priority should be a number between 1-255'],
    max: [255, 'priority should be a number between 1-255']
  },
  trackInterfacesOptional: {
    type: [String],
    required: false,
    validate: {
      validator: val => val.every(validateDevId),
      message: 'Track interfaces should contains only a valid interface devIds'
    },
    default: []
  },
  trackInterfacesMandatory: {
    type: [String],
    required: false,
    validate: {
      validator: val => val.every(validateDevId),
      message: 'Track interfaces should contains only a valid interface devIds'
    },
    default: []
  },
  jobStatus: {
    type: String,
    enum: ['installed', 'pending', 'failed', 'removed']
  }
}, {
  timestamps: false
});

/**
 * VRRP Schema
 */

const vrrpSchema = new Schema({
  org: {
    type: Schema.Types.ObjectId,
    ref: 'organizations',
    required: true
  },
  name: {
    type: String,
    required: true,
    maxlength: [30, 'Name length must be at most 30']
  },
  virtualRouterId: {
    type: Number,
    required: true,
    min: [1, 'virtualRouterId should be a number between 1-255'],
    max: [255, 'virtualRouterId should be a number between 1-255']
  },
  virtualIp: {
    type: String,
    maxlength: [20, 'virtualIp length must be at most 20'],
    validate: {
      validator: validateIPv4,
      message: 'virtualIp should be a valid ip address'
    }
  },
  preemption: {
    type: Boolean,
    default: true,
    required: true
  },
  acceptMode: {
    type: Boolean,
    default: false,
    required: true
  },
  devices: [vrrpDeviceSchema]
}, {
  timestamps: true
});

// used for search many times so better to index it.
vrrpSchema.index({ org: 1, 'devices.device': 1 }, { unique: false });

module.exports = mongoConns.getMainDB().model('vrrp', vrrpSchema);
