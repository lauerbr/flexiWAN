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

/* eslint-disable max-len */
const resources = require('../resources');
const mongoose = require('mongoose');

let resourcesFullSchema;

beforeEach(() => {
  // eslint-disable-next-line new-cap
  resourcesFullSchema = new resources({
    username: 'user1',
    key: 'kfir4ksif4psom1jdos0i93id02nski40oskri203is94iswjf',
    link: 'https://example.com',
    downloadObject: mongoose.Types.ObjectId('4edd40c86762e0fb12000003'),
    type: 'token',
    fileName: 'file.txt',
    fieldName: 'created a file'
  });
});

describe('Minimal required resources schema', () => {
  it('Should be a valid resource model if all required fields are present', () => {
    resourcesFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid resource model if username filed is missing', () => {
    resourcesFullSchema.username = null;

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: username: Path `username` is required.');
    });
  });

  it('Should be an invalid resource model if key filed is missing', () => {
    resourcesFullSchema.key = null;

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: key: Path `key` is required.');
    });
  });

  it('Should be an invalid resource model if link filed is missing', () => {
    resourcesFullSchema.link = null;

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: link: Path `link` is required.');
    });
  });

  it('Should be an invalid resource model if downloadObject filed is missing', () => {
    resourcesFullSchema.downloadObject = null;

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: downloadObject: Download object must be set');
    });
  });

  it('Should be an invalid resource model if type filed is missing', () => {
    resourcesFullSchema.type = null;

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: type: Path `type` is required.');
    });
  });
});

describe('Resources schema', () => {
  it('Should be a valid resource model if all fields are valid', () => {
    resourcesFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid resource model if username filed is invalid', () => {
    resourcesFullSchema.username = 'invalid-username';

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: username: should be a valid ' +
                                     'email address or contain English characters, digits and .');
    });
  });

  it('Should be an invalid resource model if key filed is invalid', () => {
    resourcesFullSchema.key = '!@#$%^!@#$%^!@#$%^!@#$%^!@#$%^!@#$%^!@#$%^!@#$%^!@';

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: key: Key must be letters or numbers only');
    });
  });

  it('Should be an invalid resource model if link filed is invalid', () => {
    resourcesFullSchema.link = 'http://invalid%link.com';

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: link: should be a valid url');
    });
  });

  it('Should be an invalid resource model if type filed is invalid', () => {
    resourcesFullSchema.type = 'invalid-type-field#$%^';

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: type: Only token types supported');
    });
  });

  it('Should be an invalid resource model if fileName filed is invalid', () => {
    resourcesFullSchema.fileName = '../../invalid-fila-name';

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: fileName: should be a valid file name');
    });
  });

  it('Should be an invalid resource model if fieldName filed is invalid', () => {
    resourcesFullSchema.fieldName = 'invalid_field_name';

    resourcesFullSchema.validate((err) => {
      expect(err.message).toBe('resources validation failed: fieldName: should be a valid field name');
    });
  });
});
