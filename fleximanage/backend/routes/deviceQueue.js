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

const configs = require('../configs')();
const express = require('express');
const bodyParser = require('body-parser');
const createError = require('http-errors');
const cors = require('./cors');
const { verifyPermission } = require('../authenticate');
const deviceQueueRouter = express.Router();
deviceQueueRouter.use(bodyParser.json());
const deviceQueues = require('../utils/deviceQueue')(
  configs.get('kuePrefix'),
  configs.get('redisUrl')
);
const logger = require('../logging/logging')({ module: module.filename, type: 'job' });

// Get stats operation for all devices
deviceQueueRouter.route('/:state')
// When options message received, reply origin based on whitelist
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
// Retrieve the list of devices
  .get(cors.corsWithOptions, verifyPermission('devices', 'get'), async (req, res, next) => {
    const state = req.params.state;
    const stateOpts = ['complete', 'failed', 'inactive', 'delayed', 'active'];
    // Check state provided is allowed
    if (!stateOpts.includes(state) && state !== 'all') {
      return next(createError(400, 'Unsupported query state'));
    }

    // Generate and send the result
    const result = [];
    try {
      if (state === 'all') {
        await Promise.all(
          stateOpts.map(async (s) => {
            await deviceQueues.iterateJobsByOrg(req.user.defaultOrg._id.toString(), s,
              (job) => result.push(job));
          })
        );
      } else {
        await deviceQueues.iterateJobsByOrg(req.user.defaultOrg._id.toString(), state,
          (job) => result.push(job));
      }
      return res.status(200).send(result);
    } catch (err) {
      return next(createError(500, 'Error getting jobs info'));
    }
  })
// delete device and create a new job for this
  .delete(cors.corsWithOptions, verifyPermission('devices', 'del'), async (req, res, next) => {
    const state = req.params.state;
    const stateOpts = ['complete', 'failed', 'inactive', 'delayed', 'active'];
    // Check state provided is allowed
    if (!stateOpts.includes(state) && state !== 'all') {
      return next(createError(400, 'Unsupported query state'));
    }

    logger.info('Deleting jobs',
      {
        params: {
          org: req.user.defaultOrg._id.toString(),
          state: req.params.state,
          jobs: req.body
        },
        req: req
      });
    try {
      await deviceQueues.removeJobIdsByOrg(req.user.defaultOrg._id.toString(), req.body);
      return res.status(200).send({ ok: 1 });
    } catch (err) {
      return next(createError(500, 'Error deleting jobs'));
    }
  });

// Default exports
module.exports = deviceQueueRouter;
