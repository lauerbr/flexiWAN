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
const tunnelids = require('../tunnelids');
const mongoose = require('mongoose');

let tunnelIdsFullSchema;

beforeEach(() => {
  // eslint-disable-next-line new-cap
  tunnelIdsFullSchema = new tunnelids({
    org: mongoose.Types.ObjectId('4edd40c86762e0fb12000001'),
    nextAvailID: '1'
  });
});

describe('Minimal required tunnelids schema', () => {
  it('Should be a valid token model if all required fields are present', () => {
    tunnelIdsFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid tunnelID model if org field is missing', () => {
    tunnelIdsFullSchema.org = null;

    tunnelIdsFullSchema.validate((err) => {
      expect(err.message).toBe('tunnelID validation failed: org: Path `org` is required.');
    });
  });

  it('Should be an invalid tunnelID model if nextAvailID field is missing', () => {
    tunnelIdsFullSchema.nextAvailID = null;

    tunnelIdsFullSchema.validate((err) => {
      expect(err.message).toBe('tunnelID validation failed: nextAvailID: Next available number must be set');
    });
  });
});

describe('TunnelIDs schema', () => {
  it('Should be a valid token model if all required fields are valid', () => {
    tunnelIdsFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid tunnelID model if org field is invalid', () => {
    tunnelIdsFullSchema.org = 'invalid-org';

    tunnelIdsFullSchema.validate((err) => {
      expect(err.message).toBe('tunnelID validation failed: org: Cast to ObjectId failed ' +
            'for value "invalid-org" (type string) at path "org"');
    });
  });

  it('Should be an invalid tunnelID model if nextAvailID field is not a number', () => {
    tunnelIdsFullSchema.nextAvailID = 'not a number';

    tunnelIdsFullSchema.validate((err) => {
      expect(err.message).toBe('tunnelID validation failed: nextAvailID: Cast to Number failed ' +
                               'for value "not a number" (type string) at path "nextAvailID"');
    });
  });
});
