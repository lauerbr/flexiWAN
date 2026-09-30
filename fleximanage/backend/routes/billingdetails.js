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
const createError = require('http-errors');
const { verifyPermission } = require('../authenticate');
const flexibilling = require('../flexibilling');

const router = express.Router();
router.use(bodyParser.json());

// Retrieves the billing informtaion
router.route('/')
  .get(cors.corsWithOptions, verifyPermission('billing', 'get'), async (req, res, next) => {
    const customerId = req.user.defaultAccount.billingCustomerId;

    if (!customerId) {
      return next(createError(500, 'Unknown account error'));
    }

    const usage = await flexibilling.getCurrentUsage({ customer_id: customerId });

    return res.status(200).json({ usage });
  });

// Default exports
module.exports = router;
