/* eslint-disable no-multi-str */
/* eslint-disable no-template-curly-in-string */
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

const Service = require('./Service');
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });
const Vrrp = require('../models/vrrp');
const { devices } = require('../models/devices');
const { getAccessTokenOrgList } = require('../utils/membershipUtils');
const ObjectId = require('mongoose').Types.ObjectId;
const { isEqual, keyBy } = require('lodash');
const { queue } = require('../deviceLogic/vrrp');
const cidr = require('cidr-tools');
const deviceStatus = require('../periodic/deviceStatus')();
const { getMajorVersion, getMinorVersion } = require('../versioning');
const { checkOverlapping } = require('../utils/networks');
const { isLocalOrBroadcastAddress } = require('../deviceLogic/validators');

class VrrpService {
  static selectVrrpGroupParams (vrrpGroup) {
    vrrpGroup._id = vrrpGroup._id.toString();
    vrrpGroup.org = vrrpGroup.org.toString();
    vrrpGroup.devices = vrrpGroup.devices.map(d => {
      return {
        _id: d._id.toString(),
        device: d.device.toString(),
        interface: d.interface.toString(),
        trackInterfacesOptional: d.trackInterfacesOptional,
        trackInterfacesMandatory: d.trackInterfacesMandatory,
        priority: d.priority
      };
    });

    return vrrpGroup;
  }

  /**
   * Get all VRRP groups
   *
   * returns List
   **/
  static async vrrpGET ({ org, deviceId }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, false);
      const query = { org: { $in: orgList } };
      if (deviceId) {
        query['devices.device'] = deviceId;
      }
      const result = await Vrrp.find(query)
        .populate('devices.device', '_id name machineId')
        .lean();

      const vrrpGroups = result.map(vrrp => {
        return {
          name: vrrp.name,
          virtualRouterId: vrrp.virtualRouterId,
          virtualIp: vrrp.virtualIp,
          devices: vrrp.devices.map(d => {
            const machineId = d.device.machineId;
            const status = deviceStatus.getDeviceVrrpStatus(machineId, vrrp.virtualRouterId);

            return {
              name: d.device.name,
              _id: d.device._id.toString(),
              jobStatus: d.jobStatus,
              status: status,
              interface: d.interface
            };
          }),
          _id: vrrp._id.toString()
        };
      });

      return Service.successResponse(vrrpGroups);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
   * Create new VRRP Group
   *
   * VrrpGroup VrrpGroup
   * returns VRRP Group
   **/
  static async vrrpPOST ({ org, ...vrrpGroup }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, true);

      const { valid, err } = await VrrpService.validateVrrp(vrrpGroup, orgList[0].toString());
      if (!valid) {
        throw new Error(err);
      }

      const newVrrpGroup = await Vrrp.create({ ...vrrpGroup, org: orgList[0].toString() });

      // populate for the dispatcher only. For rest API we need to return it as is.
      let updated = await newVrrpGroup.populate(
        'devices.device', 'machineId name _id interfaces dhcp'
      ).execPopulate();
      updated = newVrrpGroup.toObject();
      const { ids, reasons } = await queue(
        null,
        updated,
        orgList[0].toString(),
        user
      );

      return Service.successResponse({
        vrrpGroup: newVrrpGroup,
        metadata: { jobs: ids.length, reasons }
      });
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
  * Update a VRRP Group
  **/
  static async vrrpIdPUT ({ id, org, ...vrrpGroup }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, true);

      const origVrrp = await Vrrp.findOne(
        { _id: id, org: { $in: orgList } }
      ).populate('devices.device', 'machineId name _id interfaces dhcp').lean();
      if (!origVrrp) {
        logger.error('Failed to get VRRP Group', {
          params: { id, orgList }
        });
        return Service.rejectResponse('VRRP Group is not found', 404);
      }

      const { valid, err } = await VrrpService.validateVrrp(vrrpGroup, orgList[0].toString());
      if (!valid) {
        throw new Error(err);
      }

      // keep the status fields in the devices if exists, don't override it with user info
      const origDevices = keyBy(origVrrp.devices, '_id');
      for (const vrrpDevice of vrrpGroup.devices) {
        if (vrrpDevice._id in origDevices) {
          vrrpDevice.jobStatus = origDevices[vrrpDevice._id].jobStatus;
        }
      }

      const updatedVrrpGroup = await Vrrp.findOneAndUpdate(
        { _id: id }, // no need to check for org as it was checked before
        vrrpGroup,
        { upsert: false, new: true, runValidators: true }
      ).populate('devices.device', 'machineId name _id interfaces dhcp').lean();

      if (isEqual(origVrrp, updatedVrrpGroup)) {
        const returnValue = VrrpService.selectVrrpGroupParams(updatedVrrpGroup);
        return Service.successResponse(returnValue, 200);
      }

      const { ids, reasons } = await queue(
        origVrrp,
        updatedVrrpGroup,
        orgList[0].toString(),
        user
      );

      const returnValue = VrrpService.selectVrrpGroupParams(updatedVrrpGroup);
      return Service.successResponse({
        vrrpGroup: returnValue,
        metadata: { jobs: ids.length, reasons }
      });
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
  * Delete VRRP Group
  **/
  static async vrrpIdDELETE ({ id, org }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, true);

      const origVrrp = await Vrrp.findOne(
        { _id: id, org: { $in: orgList } }
      ).populate('devices.device', 'machineId name _id interfaces dhcp').lean();
      if (!origVrrp) {
        return Service.rejectResponse('VRRP Group is not found', 404);
      }

      await Vrrp.deleteOne({ _id: id, org: { $in: orgList } });

      await queue(
        origVrrp,
        null,
        orgList[0].toString(),
        user
      );

      return Service.successResponse(null, 204);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
  * Get a VRRP Group
  **/
  static async vrrpIdGET ({ id, org }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, true);

      const vrrpGroup = await Vrrp.findOne({ _id: id, org: { $in: orgList } }).lean();
      if (!vrrpGroup) {
        logger.error('Failed to get VRRP Group', {
          params: { id, org, orgList }
        });
        return Service.rejectResponse('VRRP Group is not found', 404);
      }

      const returnValue = VrrpService.selectVrrpGroupParams(vrrpGroup);
      return Service.successResponse(returnValue, 200);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
  * Get devices which overlapping with the virtualIP
  **/
  static async vrrpDeviceVrrpInterfacesGET ({ org, virtualIp }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, true);
      const pipeline = [
        {
          $match: {
            org: { $in: orgList.map(o => ObjectId(o)) }
          }
        },
        {
          $project: {
            _id: 1,
            name: 1,
            versions: 1,
            interfaces: {
              $map: {
                input: {
                  $filter: {
                    input: '$interfaces',
                    as: 'ifc',
                    cond: {
                      $and: [
                        { $eq: ['$$ifc.isAssigned', true] },
                        { $ne: ['$$ifc.deviceType', 'wifi'] }
                      ]
                    }
                  }
                },
                as: 'ifc',
                in: {
                  devId: '$$ifc.devId',
                  name: '$$ifc.name',
                  dhcp: '$$ifc.dhcp',
                  type: '$$ifc.type',
                  IPv4: { $concat: ['$$ifc.IPv4', '/', '$$ifc.IPv4Mask'] }
                }
              }
            }
          }
        },
        {
          $addFields: {
            subnets: {
              $map: {
                input: '$interfaces',
                as: 'ifc',
                in: '$$ifc.IPv4'
              }
            }
          }
        },
        {
          $addFields: {
            isOverlapping: {
              $function: {
                body: checkOverlapping.toString(),
                args: ['$subnets', [virtualIp + '/32']],
                lang: 'js'
              }
            }
          }
        },
        { $match: { 'isOverlapping.0': { $exists: true } } },
        { $unset: ['isOverlapping', 'subnets'] },
        {
          $addFields: {
            interfaces: {
              $arrayToObject: {
                $map: {
                  input: '$interfaces',
                  in: { k: '$$this.devId', v: '$$this' }
                }
              }
            }
          }
        }
      ];

      const data = await devices.aggregate(pipeline).allowDiskUse(true);

      const result = [];
      for (const device of data) {
        const majorVersion = getMajorVersion(device.versions.device);
        const minorVersion = getMinorVersion(device.versions.device);
        if (majorVersion < 6 || (majorVersion === 6 && minorVersion <= 2)) {
          continue;
        }

        result.push({
          ...device,
          _id: device._id.toString()
        });
      }
      return result;
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  static async validateVrrp (vrrp, org) {
    const devicesIds = vrrp.devices.map(d => d.device);
    const devicesList = await devices.find({
      org: org, _id: { $in: devicesIds }
    }, '_id interfaces name').lean();
    if (devicesList.length !== vrrp.devices.length) {
      return {
        valid: false,
        err: 'Some or all VRRP devices are not exists'
      };
    }

    const devicesById = keyBy(devicesList, '_id');
    for (const vrrpDevice of vrrp.devices) {
      if (!(vrrpDevice?.device in devicesById)) {
        return {
          valid: false,
          err: `Device ID ${vrrpDevice.device} is not exists`
        };
      }

      const deviceName = devicesById[vrrpDevice.device].name;
      // check that interface IDs are exists.
      const interfacesByDevId = keyBy(devicesById[vrrpDevice.device].interfaces, 'devId');
      if (!(vrrpDevice.interface in interfacesByDevId)) {
        return {
          valid: false,
          err: `Interface devId ${vrrpDevice.interface} is not exists in device ${deviceName}`
        };
      }

      const ifc = interfacesByDevId[vrrpDevice.interface];

      if (!ifc.isAssigned) {
        return {
          valid: false,
          err: `The interface ${ifc.name} is not assigned`
        };
      }

      if (ifc.type === 'WAN') {
        return {
          valid: false,
          err: `VRRP cannot be configured on a WAN interface (${ifc.name})`
        };
      }

      if (ifc.deviceType === 'wifi') {
        return {
          valid: false,
          err: `VRRP cannot be configured on a WiFi interface (${ifc.name})`
        };
      }

      const ip = `${ifc.IPv4}/${ifc.IPv4Mask}`;
      if (!cidr.overlap(ip, `${vrrp.virtualIp}/32`)) {
        return {
          valid: false,
          err: `The interface ${ifc.name}'s IP ${ip} is not ` +
          `overlapping with the VRRP's virtual IP ${vrrp.virtualIp}`
        };
      }

      if (isLocalOrBroadcastAddress(vrrp.virtualIp, ifc.IPv4Mask)) {
        return {
          valid: false,
          err: `The virtual IP ${vrrp.virtualIp} cannot be Network or Broadcast IP`
        };
      }

      const tracked = [
        ...vrrpDevice.trackInterfacesOptional ?? [],
        ...vrrpDevice.trackInterfacesMandatory ?? []
      ];
      for (const trackIfcs of tracked) {
        if (!(trackIfcs in interfacesByDevId)) {
          return {
            valid: false,
            err: `Track interface devId ${trackIfcs} is not exists in device ${deviceName}`
          };
        }
      }
      // duplication of interfaces
      const uniqueTrackedInterfaces = new Set(tracked);
      if (uniqueTrackedInterfaces.size !== tracked.length) {
        return {
          valid: false,
          err: 'It looks like you have duplicates in the tracked interfaces lists'
        };
      }
    }

    // get other vrrp groups in the org.
    const vrrpGroups = await Vrrp.find({ _id: { $ne: vrrp._id }, org }).lean();

    const usedInterfaces = new Set();
    const usedGroupIds = new Set();
    for (const vrrpGroup of vrrpGroups) {
      const groupId = vrrpGroup.virtualRouterId;
      usedGroupIds.add(groupId);

      for (const vrrpGroupDevice of vrrpGroup.devices) {
        const key = `${vrrpGroupDevice.interface.toString()}-${groupId}`;
        usedInterfaces.add(key);
      }
    }

    const groupId = vrrp.virtualRouterId;
    if (usedGroupIds.has(+groupId)) {
      return {
        valid: false,
        err: `Virtual Router ID ${groupId} already exists in your organization`
      };
    }

    for (const vrrpGroupDevice of vrrp.devices) {
      const key = `${vrrpGroupDevice.interface}-${groupId}`;
      if (usedInterfaces.has(key)) {
        return {
          valid: false,
          err: 'Interface is already used in another VRRP group with the same Virtual Router ID'
        };
      }
    }

    return { valid: true, err: '' };
  }

  /**
  * Get devices which overlapping with the virtualIP
  **/
  static async vrrpStatusGET ({ org }, { user }) {
    try {
      const orgList = await getAccessTokenOrgList(user, org, false);
      const vrrpGroups = await Vrrp.find({ org: orgList[0] })
        .populate('devices.device', '_id name machineId')
        .lean();

      const res = vrrpGroups.map(vrrpGroup => {
        for (const vrrpDevice of vrrpGroup.devices) {
          const machineId = vrrpDevice.device.machineId;
          const status = deviceStatus.getDeviceVrrpStatus(machineId, vrrpGroup.virtualRouterId);
          vrrpDevice.status = status;
        }
        return {
          _id: vrrpGroup._id.toString(),
          name: vrrpGroup.name,
          virtualRouterId: vrrpGroup.virtualRouterId,
          virtualIp: vrrpGroup.virtualIp,
          devices: vrrpGroup.devices.map(d => {
            return {
              _id: d.device._id.toString(),
              priority: d.priority,
              name: d.device.name,
              status: d.status
            };
          })
        };
      });

      return Service.successResponse(res);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }
}

module.exports = VrrpService;
