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

const validators = require('../validators');

describe('validateUserName', () => {
  it.each`
        name                    | result
        ${'usera'}              | ${true}
        ${'UserA'}              | ${true}
        ${'User.A'}             | ${true}
        ${'User1'}              | ${true}
        ${'User1234'}           | ${true}
        ${'USERABC'}            | ${true}
        ${'user@mail.com'}      | ${true}
        ${'maxUserNameLen.'}    | ${true}
        ${'u'}                  | ${false}
        ${'user A'}             | ${true}
        ${'User#A'}             | ${false}
        ${'TooLongUserName.'}   | ${false}
        ${'@mail'}              | ${false}
        ${''}                   | ${false}
        ${null}                 | ${false}
        ${undefined}            | ${false}
  `('Should return $result if user name is $name', ({ name, result }) => {
    expect(validators.validateUserName(name)).toEqual(result);
  });
});

describe('validateEmail', () => {
  it.each`
        email                   | result
        ${'user@mail.com'}      | ${true}
        ${'@mail'}              | ${false}
        ${'invalid.email'}      | ${false}
        ${''}                   | ${false}
        ${null}                 | ${false}
        ${undefined}            | ${false}
  `('Should return $result if email is $email', ({ email, result }) => {
    expect(validators.validateEmail(email)).toEqual(result);
  });
});

describe('validatePhoneNumber', () => {
  it.each`
        phoneNumber              | result
        ${'+1-208-7979791'}      | ${true}
        ${'+1(208)7979791'}      | ${true}
        ${'+1-208-797991'}       | ${false}
        ${''}                    | ${false}
  `('Should return $result if phoneNumber is $phoneNumber', ({ phoneNumber, result }) => {
    expect(validators.validateIsPhoneNumber(phoneNumber)).toEqual(result);
  });
});
