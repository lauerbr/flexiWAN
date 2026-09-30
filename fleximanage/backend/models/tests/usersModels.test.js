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
const users = require('../users');

let userFullSchema;

beforeEach(() => {
  // eslint-disable-next-line new-cap
  userFullSchema = new users({
    admin: true,
    name: 'Jean Marc',
    lastName: 'Smith',
    email: 'john.smith@company.com',
    username: 'john.smith@company.com',
    jobTitle: 'Engineer',
    phoneNumber: '+1-208-7979791',
    state: 'unverified'

  });
});

describe('Minimal required users schema', () => {
  it('Should be a valid users model if all required fields are present', () => {
    userFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid users model if name field is missing', () => {
    userFullSchema.name = null;

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: name: Path `name` is required.');
    });
  });

  it('Should be an invalid users model if email field is missing', () => {
    userFullSchema.email = null;

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: email: Path `email` is required.');
    });
  });

  it('Should be an invalid users model if username field is missing', () => {
    userFullSchema.username = null;

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: username: Path `username` is required.');
    });
  });

  it('Should be an invalid users model if jobTitle field is missing', () => {
    userFullSchema.jobTitle = null;

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: jobTitle: Path `jobTitle` is required.');
    });
  });
});

describe('Users schema', () => {
  it('Should be a valid users model if all required fields are valid', () => {
    userFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be an invalid user model if name field is invalid', () => {
    userFullSchema.name = 'invalid*name';

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: name: should be a valid first name (English chars, digits, space or -.)');
    });
  });

  it('Should be an invalid user model if lastName field is invalid', () => {
    userFullSchema.lastName = 'invalid*Lastname';

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: lastName: should be a valid last name (English chars, digits, space or -.)');
    });
  });

  it('Should be an invalid user model if email field is invalid', () => {
    userFullSchema.email = 'invalid-email-address';

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: email: should be a valid email address');
    });
  });

  it('Should be an invalid user model if username field is invalid', () => {
    userFullSchema.username = 'invalid-user-name';

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: username: should be a valid user name as email');
    });
  });

  it('Should be an invalid user model if jobTitle field is invalid', () => {
    userFullSchema.jobTitle = 'invalid*jobTitle';

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: jobTitle: should contain letters digits space or dash characters');
    });
  });

  it('Should be an invalid user model if phoneNumber field is invalid', () => {
    userFullSchema.phoneNumber = '+1-208-797979';

    userFullSchema.validate((err) => {
      expect(err.message).toBe('users validation failed: phoneNumber: should be a valid phone number');
    });
  });

  it('Should be a valid user model if phoneNumber field is empty', () => {
    userFullSchema.phoneNumber = '';

    userFullSchema.validate((err) => {
      expect(err).toBe(null);
    });
  });
});
