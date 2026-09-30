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

describe('validateURL', () => {
  it.each`
        url                                     | result
        ${'http://www.test.com'}                | ${true}
        ${'http://www.test.com/%20hello'}       | ${true}
        ${'http://www.test.com/`resource'}      | ${false}
        ${'http://www.test.com/%1'}             | ${false}
        ${'http://www.test.com/<script>'}       | ${false}
        ${''}                                   | ${false}
        ${null}                                 | ${false}
        ${undefined}                            | ${false}
  `('Should return $result if url is $url', ({ url, result }) => {
    expect(validators.validateURL(url)).toEqual(result);
  });
});

describe('validateFileName', () => {
  it.each`
        name                        | result
        ${'file.txt'}               | ${true}
        ${'file.log'}               | ${true}
        ${'../../password'}         | ${false}
        ${'..'}                     | ${false}
        ${'<file.txt>'}             | ${false}
        ${'file/name'}              | ${false}
        ${'some\\file.txt'}         | ${false}
        ${''}                       | ${false}
        ${null}                     | ${false}
        ${undefined}                | ${false}
  `('Should return $result if file name is $name', ({ name, result }) => {
    expect(validators.validateFileName(name)).toEqual(result);
  });
});

describe('validateFieldName', () => {
  it.each`
        name                        | result
        ${'Some field name'}        | ${true}
        ${'field name 1'}           | ${true}
        ${'field/name'}             | ${false}
        ${'$#@%!'}                  | ${false}
        ${'<fieldname>'}            | ${false}
        ${''}                       | ${false}
        ${null}                     | ${false}
        ${undefined}                | ${false}
  `('Should return $result if file name is $name', ({ name, result }) => {
    expect(validators.validateFieldName(name)).toEqual(result);
  });
});
