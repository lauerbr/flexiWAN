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

const {
  validateLabelName,
  validateLabelColor
} = require('../validators');

describe('validateLabelName', () => {
  const maxLabelPathName = 'Label name maximal name length';
  const tooLongLabelPathName = 'A too long Label name length is not allowed';
  it.each`
        name                    | result
        ${'MPLS'}               | ${true}
        ${'High speed fiber'}   | ${true}
        ${'a.label'}            | ${true}
        ${'label 1'}            | ${true}
        ${'M-p-L-s'}            | ${true}
        ${'M_P_L_S'}            | ${true}
        ${'maxUserNameLen.'}    | ${true}
        ${maxLabelPathName}     | ${true}
        ${'u'}                  | ${false}
        ${'Label#A'}            | ${false}
        ${'Label@A'}            | ${false}
        ${'$%^&*()'}            | ${false}
        ${''}                   | ${false}
        ${null}                 | ${false}
        ${undefined}            | ${false}
        ${tooLongLabelPathName} | ${false}
  `('Should return $result if path label name is $name', ({ name, result }) => {
    expect(validateLabelName(name)).toEqual(result);
  });
});

describe('validateLabelColor', () => {
  it.each`
        color           | result
        ${'#FFFFFF'}    | ${true}
        ${'#0A0B0C'}    | ${true}
        ${'#FF'}        | ${false}
        ${'#'}          | ${false}
        ${''}           | ${false}
        ${null}         | ${false}
        ${undefined}    | ${false}
  `('Should return $result if color is $color', ({ color, result }) => {
    expect(validateLabelColor(color)).toEqual(result);
  });
});
