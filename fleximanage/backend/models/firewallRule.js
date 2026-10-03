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

const { Schema, Types } = require('mongoose');
const {
  validateFirewallDevId,
  validateIPv4WithMask,
  validateIPv4,
  validateIPv4Prefix,
  validatePort,
  validatePortRange
} = require('./validators');

// LAN NAT parameters
const lanNat = {
  match: {
    type: String,
    required: false,
    maxlength: [20, 'IP length must be at most 20'],
    validate: {
      validator: ip => validateIPv4WithMask(ip) && validateIPv4Prefix(ip),
      message: 'Match IP should be a valid IP address'
    }
  },
  action: {
    type: String,
    required: false,
    maxlength: [20, 'IP length must be at most 20'],
    validate: {
      validator: ip => validateIPv4WithMask(ip) && validateIPv4Prefix(ip),
      message: 'Action IP should be a valid IP address'
    }
  }
};

// Source classification schema
const sourceClassificationSchema = new Schema({
  _id: false,
  ipPort: {
    ip: {
      type: String,
      maxlength: [20, 'ip length must be at most 20'],
      validate: {
        validator: validateIPv4WithMask,
        message: 'IPv4 should be a valid ip address'
      }
    },
    ports: {
      type: String,
      validate: {
        validator: validatePortRange,
        message: 'ports should be a valid ports range'
      }
    }
  },
  trafficId: {
    type: String,
    maxlength: [25, 'trafficId must be at most 25']
  },
  lanNat: {
    interface: {
      type: String,
      required: false,
      validate: {
        validator: validateFirewallDevId,
        message: 'interface should be a valid interface devId'
      }
    },
    ...lanNat
  }
});

// Destination classification schema
const destinationClassificationSchema = new Schema({
  _id: false,
  ipProtoPort: {
    ip: {
      type: String,
      maxlength: [20, 'ip length must be at most 20'],
      validate: {
        validator: validateIPv4WithMask,
        message: 'IPv4 should be a valid ip address'
      }
    },
    ports: {
      type: String,
      validate: {
        validator: validatePortRange,
        message: 'ports should be a valid ports range'
      }
    },
    protocols: {
      type: [String],
      default: undefined,
      required: false,
      enum: ['tcp', 'udp', 'icmp']
    },
    interface: {
      type: String,
      validate: {
        validator: validateFirewallDevId,
        message: 'interface should be a valid interface devId'
      }
    }
  },
  trafficId: {
    type: String,
    maxlength: [25, 'trafficId must be at most 25']
  },
  trafficTags: {
    category: {
      type: String,
      maxlength: [20, 'category must be at most 20']
    },
    serviceClass: {
      type: String,
      maxlength: [20, 'service class must be at most 20']
    },
    importance: {
      type: String,
      enum: ['', 'high', 'medium', 'low']
    }
  },
  lanNat: lanNat
});

// Rule schema
const firewallRuleSchema = new Schema({
  description: {
    type: String,
    required: false,
    maxlength: [100, 'Rule description length must be at most 100']
  },
  direction: {
    type: String,
    enum: ['inbound', 'outbound', 'lanNat'],
    default: 'inbound',
    required: true
  },
  inbound: {
    type: String,
    enum: ['edgeAccess', 'portForward', 'nat1to1'],
    default: 'edgeAccess',
    required: true
  },
  internalIP: {
    type: String,
    validate: {
      validator: validateIPv4,
      message: 'Internal IP should be a valid ip address'
    },
    required: false
  },
  internalPortStart: {
    type: String,
    validate: {
      validator: validatePort,
      message: 'Port format is invalid'
    },
    required: false
  },
  priority: {
    type: Number,
    min: [-1000, 'priority should be a number between -1000 - 1000'],
    max: [1000, 'priority should be a number between 0 - 1000'],
    required: true
  },
  enabled: {
    type: Boolean,
    default: true,
    required: true
  },
  classification: {
    source: {
      type: sourceClassificationSchema,
      default: () => ({})
    },
    destination: {
      type: destinationClassificationSchema,
      default: () => ({})
    }
  },
  action: {
    type: String,
    enum: ['allow', 'deny'],
    default: 'allow',
    required: true
  },
  interfaces: [{
    type: String,
    validate: {
      validator: validateFirewallDevId,
      message: 'interface should be a valid interface devId'
    }
  }],
  // indicates if rule created by the system and cannot be modified by a user
  system: {
    type: Boolean,
    required: true,
    default: false
  },
  // In the case of a system rule, save some reference that associates
  // it with another component in the system (an app for example)
  reference: {
    type: Types.ObjectId,
    required: false,
    refPath: 'referenceModel'
  },
  referenceModel: {
    type: String,
    required: false,
    enum: ['applications']
  },
  referenceNumber: {
    type: Number,
    required: false
  }
});

module.exports = { firewallRuleSchema };
