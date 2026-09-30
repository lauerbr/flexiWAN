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
const AccessToken = require('../models/accesstokens');
const cors = require('./cors');
const { verifyPermission } = require('../authenticate');
const mongoose = require('mongoose');
const createError = require('http-errors');
const { getToken } = require('../tokens');
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });

// router
const router = express.Router();
router.use(bodyParser.json());

// Retrieves the list of access tokens configured on device
router.route('/')
  .get(cors.corsWithOptions, verifyPermission('accesstokens', 'get'), (req, res, next) => {
    AccessToken
      .find({ account: req.user.defaultAccount._id })
      .populate('organization')
      .then((resp) => {
        // Organization.findById(resp.organization).then(organizations => {
        const result = resp.map(record => {
          return {
            id: record.id,
            name: record.name,
            organization: record.organization.name,
            token: record.token,
            isValid: record.isValid
          };
        });

        return res.status(200).json(result);
      }, (err) => {
        return next(createError(404, 'Error retrieving token.'));
      })
      .catch((err) => {
        return next(createError(500));
      });
  })
  // When options message received, reply origin based on whitelist
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
  // Creates new access token for the current user
  .post(cors.corsWithOptions, verifyPermission('accesstokens', 'post'), async (req, res, next) => {
    try {
      const tokenIsValid = req.user.defaultAccount.organizations.find((record) => {
        return record._id.toString() === req.body.organization;
      });

      if (!tokenIsValid) return next(createError(403, 'Error generating token.'));

      const accessToken = new AccessToken({
        account: req.user.defaultAccount._id,
        organization: req.body.organization,
        name: req.body.name,
        token: '',
        isValid: true
      });
      const token = await getToken(
        req,
        {
          type: 'app_access_token',
          id: accessToken._id.toString(),
          org: req.body.organization
        },
        false
      );
      accessToken.token = token;
      await accessToken.save();

      return res.status(201).json({ id: accessToken.id, name: accessToken.name });
    } catch (error) {
      logger.error('Could not generate token', {
        params: { user: req.user, message: error.message },
        req: req
      });
      return next(createError(500));
    }
  });

// Deletes an access token from the system
router.route('/:accesstokenId')
  // When options message received, reply origin based on whitelist
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
  .delete(cors.corsWithOptions, verifyPermission('accesstokens', 'del'), (req, res, next) => {
    AccessToken.deleteOne({
      _id: mongoose.Types.ObjectId(req.params.accesstokenId),
      account: req.user.defaultAccount._id
    })
      .then(
        resp => {
          if (resp != null) {
            return res.status(200).json({});
          } else {
            return next(createError(404, 'Access Token not found'));
          }
        },
        err => {
          return next(createError(500));
        }
      )
      .catch(err => {
        return next(createError(500));
      });
  });

// Default exports
module.exports = router;
