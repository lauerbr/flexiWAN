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
const cors = require('./cors');
const { verifyPermission } = require('../authenticate');
const User = require('../models/users');
const Accounts = require('../models/accounts');
const { getToken } = require('../tokens');
const { getUserAccounts, orgUpdateFromNull } = require('../utils/membershipUtils');
const createError = require('http-errors');
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });

const accountsRouter = express.Router();
accountsRouter.use(bodyParser.json());

// Retrieves a list of users in the system
accountsRouter.route('/')
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
// No need to check permission. User can see all the accounts he's registered to
  .get(cors.corsWithOptions, async (req, res, next) => {
    try {
      const accounts = await getUserAccounts(req.user);
      return res.status(200).json(accounts);
    } catch (err) {
      logger.error('Error getting accounts', { params: { reason: err.message } });
      return next(createError(500, 'Error getting accounts'));
    }
  });

// Select current users account
accountsRouter.route('/select')
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
// No need to check permission. User can see all the accounts he's registered to
  .post(cors.corsWithOptions, (req, res, next) => {
    if (!req.user.defaultAccount || !req.user.defaultAccount._id || !req.user._id) {
      return next(createError(500, 'Error in selecting account'));
    }
    // If current account not changed, return OK
    if (req.user.defaultAccount._id.toString() === req.body.account) {
      return res.status(200).json({ _id: req.user.defaultAccount._id });
    }

    // Get organizations for the new account
    User.findOneAndUpdate(
      // Query, use the email and account
      { _id: req.user._id },
      // Update account, set default org to null so the system
      // will choose an organization on login if something failed
      { defaultAccount: req.body.account, defaultOrg: null },
      // Options
      { upsert: false, new: true }
    )
      .populate('defaultAccount')
      .then(async (updUser) => {
        // Set a default organization for the new account
        req.user.defaultAccount = updUser.defaultAccount;
        req.user.defaultOrg = null;
        await orgUpdateFromNull(req, res);
        return res.status(200).json({ _id: updUser.defaultAccount._id });
      })
      .catch((err) => {
        logger.error('Error selecting account', { params: { reason: err.message } });
        return next(createError(500, 'Error selecting account'));
      });
  });

// Retrieves a list of accounts in the system
accountsRouter.route('/:accountId')
  .options(cors.corsWithOptions, (req, res) => { res.sendStatus(200); })
  .get(cors.corsWithOptions, verifyPermission('accounts', 'get'), (req, res, next) => {
    Accounts.findOne({ _id: req.user.defaultAccount._id })
      .then((account) => {
        const {
          logoFile,
          organizations,
          companySize,
          serviceType,
          numSites,
          __v,
          ...rest
        } = account.toObject();
        return res.status(200).json(rest);
      }, (err) => { throw err; })
      .catch((err) => {
        logger.error('Error getting account', {
          params: {
            accountId: req.user.defaultAccount._id,
            reason: err.message
          }
        });
        return next(createError('Error getting account'));
      });
  });

// Retrieves a list of users in the system
accountsRouter.route('/:accountId')
  .put(cors.corsWithOptions, verifyPermission('accounts', 'put'), async (req, res, next) => {
    try {
      delete req.body.logoFile;
      delete req.body.organizations;
      delete req.body._id;
      delete req.body.companySize;
      delete req.body.serviceType;
      delete req.body.numSites;
      const account = await Accounts.findOneAndUpdate(
        { _id: req.params.accountId },
        { $set: req.body },
        { upsert: false, new: true, runValidators: true });

      // Update token
      const token = await getToken(req, { accountName: account.name });
      res.setHeader('Refresh-JWT', token);

      // Return organization
      const {
        logoFile,
        organizations,
        companySize,
        serviceType,
        numSites,
        __v,
        ...rest
      } = account.toObject();
      return res.status(200).json(rest);
    } catch (err) {
      logger.error('Error updating account', {
        params: { accountId: req.params.accountId, reason: err.message }
      });
      return next(createError(400, err.message));
    }
  });

// Default exports
module.exports = {
  accountsRouter: accountsRouter
};
