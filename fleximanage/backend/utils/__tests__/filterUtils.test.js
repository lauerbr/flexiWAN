// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019-2025  flexiWAN Ltd.

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

const { getMatchFilters, passFilters, validateSort } = require('../filterUtils');

describe('getMatchFilters', () => {
  it('builds literal regular expressions', () => {
    const [expr] = getMatchFilters([{ key: 'name', op: 'contains', val: 'a.b(' }]);
    expect(expr.name.test('xxa.b(yy')).toBe(true);
    expect(expr.name.test('xxaXb(yy')).toBe(false);
  });

  it('keeps supported filters working', () => {
    expect(getMatchFilters([{ key: 'name', op: '==', val: 'Dev1' }])[0].name.test('dev1'))
      .toBe(true);
    expect(getMatchFilters([{ key: 'cpu', op: '>', val: 3 }])[0]).toEqual({ cpu: { $gt: 3 } });
    expect(getMatchFilters([{ key: 'state', op: 'in', val: 'a,b' }])[0])
      .toEqual({ state: { $in: ['a', 'b'] } });
    const twoSides = getMatchFilters([{ key: 'device?.name', op: '==', val: 'x' }])[0];
    expect(Object.keys(twoSides)).toEqual(['$or']);
    const multi = getMatchFilters([{ key: 'name|description', op: 'contains', val: 'x' }])[0];
    expect(multi.$or.length).toBe(2);
  });

  it('rejects operator injection in values', () => {
    expect(() => getMatchFilters([{ key: 'name', op: '==', val: { $ne: null } }])).toThrow();
    expect(() => getMatchFilters([{ key: 'name', op: 'in', val: [{ $gt: '' }] }])).toThrow();
  });

  it('rejects invalid or sensitive keys and unknown operations', () => {
    expect(() => getMatchFilters([{ key: '$where', op: '==', val: 'x' }])).toThrow();
    expect(() => getMatchFilters([{ key: 'deviceToken', op: 'contains', val: 'a' }])).toThrow();
    expect(() => getMatchFilters([{ key: 'name', op: '$regex', val: 'a' }])).toThrow();
    expect(() => getMatchFilters([{ key: 'name', op: '==', val: 'a'.repeat(300) }])).toThrow();
  });
});

describe('passFilters', () => {
  it('matches literally', () => {
    const obj = { data: { message: { title: 'a.c' } } };
    expect(passFilters(obj, [{ key: 'data.message.title', op: '==', val: 'a.c' }])).toBe(true);
    expect(passFilters({ data: { message: { title: 'abc' } } },
      [{ key: 'data.message.title', op: '==', val: 'a.c' }])).toBe(false);
    expect(passFilters(obj, [{ key: 'data.message.title', op: 'contains', val: '(a+)+$' }]))
      .toBe(false);
  });
});

describe('validateSort', () => {
  it('validates sort field and order', () => {
    expect(() => validateSort('name', 'asc')).not.toThrow();
    expect(() => validateSort('interfaces.name', 'DESC')).not.toThrow();
    expect(() => validateSort(undefined, undefined)).not.toThrow();
    expect(() => validateSort('$where', 'asc')).toThrow();
    expect(() => validateSort('deviceToken', 'asc')).toThrow();
    expect(() => validateSort('name', { a: 1 })).toThrow();
  });
});
