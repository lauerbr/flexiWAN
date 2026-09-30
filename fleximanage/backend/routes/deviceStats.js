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

const express = require('express');
const bodyParser = require('body-parser');
// const {devices} = require('../models/devices');
const cors = require('./cors');
const { verifyPermission } = require('../authenticate');
const { deviceStats } = require('../models/analytics/deviceStats');
const mongoose = require('mongoose');
const createError = require('http-errors');
const deviceStatsRouter = express.Router();
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });
deviceStatsRouter.use(bodyParser.json());

/**
 * Find device stats per organization
 * @param  {String} org - organization to search the device for
 * @param  {String} deviceID - Object ID for device to search stats for, or null for all devices
 * @param  {Epoc (sec in UTC)} startTime - returns stats from that time, if null ignores
 * @param  {Epoc (sec in UTC)} endTime - returns stats to that time, if null ignores
 * @return {Array}  Returns express response,
 *                  If deviceID==null, returns stats for all devices per time
 *                  aggregated for all interfaces, for specific device returns
 *                  stats per time listed per interface
 */
const queryDeviceStats = (req, res, next, org, deviceID, startTime, endTime) => {
  // Defind match statement
  const match = { org: mongoose.Types.ObjectId(org) };
  if (deviceID) match.device = mongoose.Types.ObjectId(deviceID);
  if (startTime && endTime) {
    match.$and = [{ time: { $gte: startTime } }, { time: { $lte: endTime } }];
  } else if (startTime) match.time = { $gte: startTime };
  else if (endTime) match.time = { $lte: endTime };

  const pipeline = [
    { $match: match },
    { $project: { time: 1, stats: { $objectToArray: '$stats' } } },
    { $unwind: '$stats' },
    {
      $group:
            {
              _id: { time: '$time', interface: 'All' },
              rx_bps: { $sum: '$stats.v.rx_bps' },
              tx_bps: { $sum: '$stats.v.tx_bps' },
              rx_pps: { $sum: '$stats.v.rx_pps' },
              tx_pps: { $sum: '$stats.v.tx_pps' }
            }
    },
    {
      $project: {
        _id: 0,
        time: '$_id.time',
        interface: '$_id.interface',
        rx_bps: '$rx_bps',
        tx_bps: '$tx_bps',
        rx_pps: '$rx_pps',
        tx_pps: '$tx_pps'
      }
    },
    { $sort: { time: -1 } }
  ];

  deviceStats.aggregate(pipeline).allowDiskUse(true).then((stats) => {
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    return res.json(stats);
  }, (err) => { next(err); })
    .catch((err) => {
      logger.warn('Failed to get device stats', { params: { err: err.message }, req: req });
      return next(createError(500, 'Getting device stats'));
    });
};
// Get stats operation for all devices
deviceStatsRouter.route('/')
// When options message received, reply origin based on whitelist
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
  .get(cors.corsWithOptions, verifyPermission('devices', 'get'), (req, res, next) => {
    queryDeviceStats(
      req,
      res,
      next,
      req.user.defaultOrg._id.toString(),
      null,
      Math.floor(new Date().getTime() / 1000) - 7200,
      null
    );
    // queryDeviceStats(req, res, next, req.user.defaultOrg._id.toString(), null, null, null);
  });

// Get stats operation for all devices
deviceStatsRouter.route('/:deviceId')
// When options message received, reply origin based on whitelist
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
  .get(cors.corsWithOptions, verifyPermission('devices', 'get'), (req, res, next) => {
    queryDeviceStats(
      req,
      res,
      next,
      req.user.defaultOrg._id.toString(),
      req.params.deviceId,
      Math.floor(new Date().getTime() / 1000) - 7200,
      null
    );
    // queryDeviceStats(req, res, next, req.user.defaultOrg._id.toString(),
    // req.params.deviceId, null, null);
  });

// Default exports
module.exports = deviceStatsRouter;
