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

const validators = require('./validators');
const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const mongoConns = require('../mongoConns.js')();

// This table holds the shared file links
const resourcesSchema = new Schema({
  // User who created this resource
  username: {
    type: String,
    required: true,
    validate: {
      validator: validators.validateUserName,
      message: 'should be a valid email address or contain English characters, digits and .'
    }
  },
  // Key as part of the URL
  key: {
    type: String,
    required: true,
    unique: true,
    maxlength: [50, 'Key length must be exactly 50'],
    minlength: [50, 'Key length must be exactly 50'],
    match: [/^[a-zA-Z0-9]{50}$/, 'Key must be letters or numbers only']
  },
  // URL for downloading the resource
  link: {
    type: String,
    required: true,
    maxlength: [255, 'Link length must be at most 255'],
    validate: {
      validator: validators.validateURL,
      message: 'should be a valid url'
    }
  },
  // Object referred by this resource
  downloadObject: {
    type: mongoose.Schema.Types.ObjectId,
    unique: true, // Allow only one resource for each object ID
    required: [true, 'Download object must be set']
  },
  // Type of resource
  type: {
    type: String, // e.g. "token"
    required: true,
    match: [/^token$/, 'Only token types supported'],
    maxlength: [20, 'Type length must be at most 20']
  },
  // File name to return
  fileName: {
    type: String, // e.g. token.txt
    default: 'unknown',
    maxlength: [100, 'File name length must be at most 100'],
    validate: {
      validator: validators.validateFileName,
      message: 'should be a valid file name'
    }
  },
  // Field to export as text
  fieldName: {
    type: String, // e.g. token generated
    default: '',
    maxlength: [100, 'Field name length must be at most 100'],
    validate: {
      validator: validators.validateFieldName,
      message: 'should be a valid field name'
    }
  }
}, {
  timestamps: true
});

// Default exports
module.exports = mongoConns.getMainDB().model('resources', resourcesSchema);
