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
const Schema = mongoose.Schema;
const mongoConns = require('../mongoConns.js')();

const ruleSchema = new Schema({
  warningThreshold: { type: Number, default: null },
  criticalThreshold: { type: Number, default: null },
  thresholdUnit: { type: String, default: null, enum: ['%', 'ms', 'C°', null] },
  severity: { type: String, default: null, enum: ['critical', 'warning', null] },
  immediateEmail: { type: Boolean, default: false },
  resolvedAlert: { type: Boolean, default: true },
  type: {
    type: String,
    required: false,
    enum: ['device', 'tunnel', 'policy', 'interface']
  },
  sendWebHook: { type: Boolean, default: false }
}, { _id: false });

const webHookSchema = new Schema({
  webhookURL: {
    type: String,
    maxlength: [256, 'Webhook URL cannot be longer than 256 characters']
  },
  sendCriticalAlerts: { type: Boolean, default: true },
  sendWarningAlerts: { type: Boolean, default: false }
}, { _id: false });

/**
 * Notifications configuration Database Schema
 */
const notificationsConfSchema = new Schema({
  name: {
    type: String
  },
  org: {
    type: Schema.Types.ObjectId,
    ref: 'organizations'
  },
  account: {
    type: Schema.Types.ObjectId,
    ref: 'accounts'
  },
  rules: {
    'Device connection': ruleSchema,
    'Running router': ruleSchema,
    'Link/Tunnel round trip time': ruleSchema,
    'Link/Tunnel default drop rate': ruleSchema,
    'Device memory usage': ruleSchema,
    'Hard drive usage': ruleSchema,
    Temperature: ruleSchema,
    'Software update': ruleSchema,
    'Internet connection': ruleSchema,
    'Link status': ruleSchema,
    'Missing interface ip': ruleSchema,
    'Tunnel connection': ruleSchema,
    'Pending tunnel': ruleSchema,
    'Failed self-healing': ruleSchema,
    'Static route state': ruleSchema
  },
  signedToCritical:
  [
    { type: mongoose.Schema.Types.ObjectId, ref: 'users' }
  ],
  signedToWarning:
  [
    { type: mongoose.Schema.Types.ObjectId, ref: 'users' }
  ],
  signedToDaily:
  [
    { type: mongoose.Schema.Types.ObjectId, ref: 'users' }
  ],
  webHookSettings: webHookSchema,
  isEnabled: {
    type: Boolean,
    default: true
  }
});

notificationsConfSchema.index({ org: 1 }, { unique: true, sparse: true });
notificationsConfSchema.index({ account: 1 }, { unique: true, sparse: true });

// Default exports
module.exports = mongoConns.getMainDB().model('notifications', notificationsConfSchema);
