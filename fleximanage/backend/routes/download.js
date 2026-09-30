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
const resourcesModel = require('../models/resources');
const tokens = require('../models/tokens');
const logger = require('../logging')({ module: module.filename, type: 'req' });
const createError = require('http-errors');

const downloadRouter = express.Router();
downloadRouter.use(bodyParser.json());

const formatErr = (err, msg) => {
  return ({ status: 500, error: 'Download error' });
};

// Get downloadable link
downloadRouter.route('/:fileId/:fileName')
  .get(cors.cors, verifyPermission('organizations', 'get'), (req, res, next) => {
    resourcesModel.find({ key: req.params.fileId })
      .then((resp) => {
        const obj = resp[0];
        // Find the file to return
        // Only tokens are supported now
        switch (obj.type) {
          case 'token':
            tokens.find({ _id: obj.downloadObject, username: obj.username })
              .then((objResp) => {
                const token = objResp[0];
                // Return the token as a file
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/octet-stream');
                res.setHeader('Content-Disposition', 'attachment; filename="' + obj.fileName + '"');
                return res.send(token[obj.fieldName]);
              }, (err) => {
                logger.warn('Failed to download token', { params: { err: err.message }, req: req });
                const fErr = formatErr(err, req.body);
                return next(createError(fErr.status, fErr.error));
              })
              .catch((err) => next(err));
            break;
          default: {
            const error = new Error('Resource type ' + obj.type + ' not supported');
            return next(error);
          }
        }
      }, (err) => {
        logger.warn('Failed to download token', { params: { err: err.message }, req: req });
        const fErr = formatErr(err, req.body);
        return next(createError(fErr.status, fErr.error));
      })
      .catch((err) => next(err));
  });

// Default exports
module.exports = downloadRouter;
