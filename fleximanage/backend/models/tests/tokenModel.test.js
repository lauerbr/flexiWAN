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

const tokens = require('../tokens');
const mongoose = require('mongoose');

let tokenFullSchema;

beforeEach(() => {
  // eslint-disable-next-line new-cap
  tokenFullSchema = new tokens({
    org: mongoose.Types.ObjectId('4edd40c86762e0fb12000001'),
    name: 'Token name',
    token: 'some JWT token'
  });
});

describe('Minimal required token schema', () => {
  it('Should be a valid token model if all required fields are present', () => {
    tokenFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid token model if org field is missing', () => {
    tokenFullSchema.org = null;

    tokenFullSchema.validate((err) => {
      expect(err.message).toBe('tokens validation failed: org: Path `org` is required.');
    });
  });

  it('Should be an invalid token model if token name field is missing', () => {
    tokenFullSchema.name = null;

    tokenFullSchema.validate((err) => {
      expect(err.message).toBe('tokens validation failed: name: Path `name` is required.');
    });
  });

  it('Should be an invalid token model if token field is missing', () => {
    tokenFullSchema.token = null;

    tokenFullSchema.validate((err) => {
      expect(err.message).toBe('tokens validation failed: token: Path `token` is required.');
    });
  });
});

describe('Token schema', () => {
  it('Should be a valid token model if all required fields are valid', () => {
    tokenFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid token model if org field is invalid', () => {
    tokenFullSchema.org = 'invalid-org';

    tokenFullSchema.validate((err) => {
      expect(err.message).toBe('tokens validation failed: org: Cast to ObjectId failed ' +
            'for value "invalid-org" (type string) at path "org"');
    });
  });

  it('Should be an invalid token model if token name field is invalid', () => {
    tokenFullSchema.name = 'invalid^token^name';

    tokenFullSchema.validate((err) => {
      expect(err.message).toBe('tokens validation failed: name: Token name format is invalid');
    });
  });
});
