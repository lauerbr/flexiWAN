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

/**
 * Get available ips from a mask
 * @param  {number} mask  subnet mask
 * @return {number}       number of available ips
 */
const getRangeAndMask = number => {
  const baseTwo = Math.ceil(Math.log2(number));
  const mask = 32 - baseTwo;
  const range = Math.pow(2, baseTwo);
  return { range, mask };
};

/**
 * Find the start and end IPv4 from ip + mask
 * @param {String} ip     IPv4 address
 * @param {String} mask   Number of bit masks
 * @param {String} shift  Number of IPs to shift from start
 */
const getStartEndIp = (ipString, mask, shift = 0) => {
  function u (n) { return n >>> 0; } // convert to unsigned
  function ip (n) {
    return [
      (n >>> 24) & 0xFF,
      (n >>> 16) & 0xFF,
      (n >>> 8) & 0xFF,
      (n >>> 0) & 0xFF
    ].join('.');
  }
  const m = ipString.split('.');
  const addr32 = m.reduce((a, o) => {
    return u(+a << 8) + +o;
  });
  const maskNum = u(~0 << (32 - +mask));
  return [ip(u(addr32 & maskNum) + shift), ip(u(addr32 | ~maskNum) - shift)];
};

function checkOverlapping (subnets1, subnets2) {
  function checkSubnetIntersection (subnet1, subnet2) {
    function u (n) { return n >>> 0; } // convert to unsigned
    function addr32 (ip) {
      const m = ip.split('.');
      return m.reduce((a, o) => { return u(+a << 8) + +o; });
    }
    const [address1, mask1] = subnet1.split('/');
    const [address2, mask2] = subnet2.split('/');

    const binAddress1 = addr32(address1);
    const binAddress2 = addr32(address2);
    const binMask1 = u(~0 << (32 - +mask1));
    const binMask2 = u(~0 << (32 - +mask2));

    const [start1, end1] = [u(binAddress1 & binMask1), u(binAddress1 | ~binMask1)];
    const [start2, end2] = [u(binAddress2 & binMask2), u(binAddress2 | ~binMask2)];

    return (
      (start1 >= start2 && start1 <= end2) ||
      (start2 >= start1 && start2 <= end1)
    );
  }

  const result = [];
  for (const subnet1 of subnets1) {
    if (subnet1 === '/') continue; // allow dhcp interface to be empty
    for (const subnet2 of subnets2) {
      if (subnet2 === '/') continue; // allow dhcp interface to be empty
      const isOverlapping = checkSubnetIntersection(subnet1, subnet2);
      if (isOverlapping) {
        result.push(subnet2);
      }
    }
  }

  return result;
}

module.exports = {
  getRangeAndMask,
  getStartEndIp,
  checkOverlapping
};
