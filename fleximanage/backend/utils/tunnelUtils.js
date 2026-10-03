// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019-2020  flexiWAN Ltd.

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

const configs = require('../configs')();
const randomNum = require('../utils/random-key');
const mongoose = require('mongoose');
const { getMatchFilters } = require('../utils/filterUtils');

/**
 * Generates various tunnel parameters that will
 * be used for creating the tunnel.
 * @param  {number} tunnelNum tunnel id
 * @param  {string} tunnelRange organization tunnel range
 * @return
 * {{
        ip1: string,
        ip2: string,
        mac1: string,
        mac2: string,
        sa1: number,
        sa2: number
    }}
 */
function generateTunnelParams (tunnelNum, tunnelRange) {
  const d2h = (d) => (('00' + (+d).toString(16)).substr(-2));

  const h = (tunnelNum % 127 + 1) * 2;
  const l = Math.floor(tunnelNum / 127);

  const splitIp = tunnelRange.split('.');
  const ipStart = `${splitIp[0]}.${splitIp[1]}.`;

  const ip1 = ipStart + (+l).toString(10) + '.' + (+h).toString(10);
  const ip2 = ipStart + (+l).toString(10) + '.' + (+(h + 1)).toString(10);
  const mac1 = '02:00:27:fd:' + d2h(l) + ':' + d2h(h);
  const mac2 = '02:00:27:fd:' + d2h(l) + ':' + d2h(h + 1);
  const sa1 = (l * 256 + h);
  const sa2 = (l * 256 + h + 1);

  return {
    ip1: ip1,
    ip2: ip2,
    mac1: mac1,
    mac2: mac2,
    sa1: sa1,
    sa2: sa2
  };
};

/**
 * Generates random keys that will be used for tunnels creation
 * @return {{key1: number, key2: number, key3: number, key4: number}}
 */
const generateRandomKeys = () => {
  return {
    key1: randomNum(32, 16),
    key2: randomNum(32, 16),
    key3: randomNum(32, 16),
    key4: randomNum(32, 16)
  };
};

/**
 * Generates a pipeline for mongoose aggregate query to get filtered tunnels
 * @return {Array} an array of query stages
 */
const getTunnelsPipeline = (orgList, filters, detailed = true) => {
  const matchPipeline = [{
    $match: {
      org: { $in: orgList.map(o => mongoose.Types.ObjectId(o)) },
      isActive: true
    }
  }];

  const dataPipeline = [
    {
      $lookup: {
        from: 'devices',
        localField: 'deviceA',
        foreignField: '_id',
        as: 'deviceA'
      }
    },
    { $unwind: '$deviceA' },
    {
      $lookup: {
        from: 'devices',
        localField: 'deviceB',
        foreignField: '_id',
        as: 'deviceB'
      }
    },
    {
      $unwind: {
        path: '$deviceB',
        preserveNullAndEmptyArrays: true // for peers we don't use deviceB
      }
    },
    {
      $lookup: {
        from: 'pathlabels',
        localField: 'pathlabel',
        foreignField: '_id',
        as: 'pathlabel'
      }
    },
    {
      $unwind: {
        path: '$pathlabel',
        preserveNullAndEmptyArrays: true
      }
    },
    {
      $addFields: {
        interfaceADetails: {
          $filter: {
            input: '$deviceA.interfaces',
            as: 'f',
            cond: {
              $eq: ['$$f._id', '$interfaceA']
            }
          }
        },
        interfaceBDetails: {
          $filter: {
            input: '$deviceB.interfaces',
            as: 'f',
            cond: {
              $eq: ['$$f._id', '$interfaceB']
            }
          }
        }
      }
    },
    { $unwind: '$interfaceADetails' },
    {
      $unwind: {
        path: '$interfaceBDetails',
        preserveNullAndEmptyArrays: true
      }
    },
    {
      $lookup: {
        from: 'peers',
        localField: 'peer',
        foreignField: '_id',
        as: 'peer'
      }
    },
    {
      $unwind: {
        path: '$peer',
        preserveNullAndEmptyArrays: true
      }
    },
    {
      $lookup: {
        from: 'organizations',
        localField: 'org',
        foreignField: '_id',
        as: 'org'
      }
    },
    {
      $unwind: {
        path: '$org'
      }
    }
  ];
  const project = {
    $project: {
      num: 1,
      isActive: 1,
      peer: 1,
      'deviceA._id': 1,
      'deviceA.machineId': 1,
      'deviceA.isConnected': 1,
      'deviceA.status': 1,
      'deviceB._id': 1,
      'deviceB.machineId': 1,
      'deviceB.isConnected': 1,
      'deviceB.status': 1,
      deviceAconf: 1,
      deviceBconf: 1,
      notificationsSettings: 1,
      isPending: 1,
      pendingReason: 1,
      'org.tunnelRange': 1,
      tunnelStatus: {
        $switch: {
          branches: [
            {
              case: {
                // tunnel status unknown if one of devices is not connected
                $or: [
                  { $eq: ['$deviceA.isConnected', false] },
                  { $eq: ['$deviceB.isConnected', false] }
                ]
              },
              then: 'N/A'
            },
            {
              case: { $eq: ['$isPending', true] },
              then: 'Pending'
            },
            {
              case: {
                $and: [
                  { $eq: ['$status', 'up'] },
                  { $eq: ['$deviceA.status', 'running'] },
                  {
                    $or: [
                      // in case of peer, there is no deviceB to check connection for
                      { $ne: ['$peer', null] },
                      { $eq: ['$deviceB.status', 'running'] }
                    ]
                  }
                ]
              },
              then: 'Connected'
            }
          ],
          default: 'Not Connected'
        }
      }
    }
  };
  if (detailed) {
    project.$project['deviceA.name'] = 1;
    project.$project['deviceA.hostname'] = 1;
    project.$project['deviceA.versions'] = 1;
    project.$project['deviceA.sync'] = 1;
    project.$project['deviceA.staticroutes'] = 1;

    project.$project['deviceB.name'] = 1;
    project.$project['deviceB.hostname'] = 1;
    project.$project['deviceB.versions'] = 1;
    project.$project['deviceB.sync'] = 1;
    project.$project['deviceB.staticroutes'] = 1;

    project.$project.interfaceA = 1;
    project.$project.interfaceB = 1;

    project.$project['interfaceADetails.name'] = 1;
    project.$project['interfaceADetails.devId'] = 1;
    project.$project['interfaceADetails.PublicPort'] = 1;
    project.$project['interfaceADetails.useFixedPublicPort'] = 1;
    project.$project['interfaceADetails.PublicIP'] = 1;
    project.$project['interfaceADetails.IPv4'] = 1;

    project.$project['interfaceBDetails.name'] = 1;
    project.$project['interfaceBDetails.devId'] = 1;
    project.$project['interfaceBDetails.PublicPort'] = 1;
    project.$project['interfaceBDetails.useFixedPublicPort'] = 1;
    project.$project['interfaceBDetails.PublicIP'] = 1;
    project.$project['interfaceBDetails.IPv4'] = 1;

    project.$project.encryptionMethod = 1;
    project.$project.advancedOptions = 1;

    project.$project['pathlabel.name'] = 1;
    project.$project['pathlabel.color'] = 1;

    project.$project['org._id'] = 1;
    project.$project['org.vxlanPort'] = 1;
  }
  dataPipeline.push(project);

  const filterPipeline = [];
  if (filters) {
    const parsedFilters = typeof filters === 'string' ? JSON.parse(filters) : filters;
    const matchFilters = getMatchFilters(parsedFilters);
    if (matchFilters.length > 0) {
      filterPipeline.push({
        $match: { $and: matchFilters }
      });
    }
  }

  return { matchPipeline, dataPipeline, filterPipeline };
};

const getOrgDefaultTunnelPort = org => {
  return org.vxlanPort || configs.get('tunnelPort');
};

// Default exports
module.exports = {
  generateTunnelParams,
  generateRandomKeys,
  getTunnelsPipeline,
  getOrgDefaultTunnelPort
};
