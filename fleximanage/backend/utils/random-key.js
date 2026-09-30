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

// Generate a random number cryptographically secured
var crandom = require('math-random');
var baseChars62 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
var baseCharsHex = '0123456789abcdef';

/**
 * Calculates a random number
 * @param  {number}        size    size of random string
 * @param  {number|string} base=62 Chars to use. If == 'hex', uses a hex base
 * @return {string} a random string
 */
function getRandom (size, base = 62) {
  let baseChars;
  if (base === 16) baseChars = baseCharsHex;
  else baseChars = baseChars62;

  let len = size ? Number.isInteger(size) ? Math.abs(size) : 1 : 1;
  let res = '';
  while (len--) {
    res += baseChars.charAt(parseInt(crandom() * baseChars.length, 10));
  }
  return res;
}

module.exports = getRandom;
