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

/**
 * Small, dependency free security helpers.
 */
const net = require('net');
const crypto = require('crypto');

/**
 * Escape a string so it can be safely embedded in a RegExp as a literal.
 * Non string values are converted to string first.
 * @param {*} str - user input
 * @return {string} escaped string
 */
const escapeRegExp = (str) => {
  return String(str ?? '').replace(/[.*+?^${}()|[\]\\/-]/g, '\\$&');
};

/**
 * Escape a value so it can be safely embedded in HTML (text or attribute).
 * @param {*} str - value to escape
 * @return {string} HTML escaped string
 */
const escapeHtml = (str) => {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

/**
 * Find the first object key that starts with '$' (a MongoDB operator) in
 * a nested object / array. Used to block NoSQL operator injection.
 * @param {*} value - value to scan
 * @param {number} maxDepth - maximum nesting to scan, deeper values are rejected
 * @return {string|null} the offending key or null if none found
 */
const findMongoOperatorKey = (value, maxDepth = 64) => {
  const stack = [{ v: value, d: 0 }];
  while (stack.length > 0) {
    const { v, d } = stack.pop();
    if (v === null || typeof v !== 'object') continue;
    if (d > maxDepth) return '<max depth exceeded>';
    for (const key of Object.keys(v)) {
      if (key.startsWith('$')) return key;
      const child = v[key];
      if (child !== null && typeof child === 'object') stack.push({ v: child, d: d + 1 });
    }
  }
  return null;
};

/**
 * Express middleware that rejects requests whose body, query or params contain
 * object keys starting with '$', so they can't be used as MongoDB operators.
 */
const mongoSanitizer = (req, res, next) => {
  for (const part of ['body', 'query', 'params']) {
    const badKey = findMongoOperatorKey(req[part]);
    if (badKey) {
      res.status(400);
      res.type('json');
      return res.json({ error: 'Invalid request parameters' });
    }
  }
  return next();
};

/**
 * Check that a value is a non-empty string with bounded length
 * @param {*} value - value to check
 * @param {number} maxLength - maximum string length
 * @return {boolean} true if value is a non empty string shorter than maxLength
 */
const isNonEmptyString = (value, maxLength = 1024) => {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength;
};

/**
 * Compare two strings in constant time (for the given length)
 * @param {string} a
 * @param {string} b
 * @return {boolean} true if equal
 */
const safeEqual = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb) && a.length === b.length;
};

// Keys whose values must never be logged or returned to non-privileged callers.
// Matching is case insensitive and done on the full key name.
const SENSITIVE_KEYS = new Set([
  'password', 'pass', 'passwd', 'newpassword', 'oldpassword', 'currentpassword',
  'token', 'accesstoken', 'refreshtoken', 'refresh-token', 'refresh-jwt', 'authorization',
  'secret', 'secretkey', 'clientsecret', 'mfasecret', 'recoverycode', 'captcha',
  'privatekey', 'private_key', 'key', 'apikey', 'api_key',
  'psk', 'presharedkey', 'pin', 'puk', 'pincode',
  'md5password', 'bgppassword', 'authkey', 'auth_key',
  'cakey', 'serverkey', 'tlskey', 'tls_key', 'crypto_key', 'integr_key',
  'local_sa_key', 'remote_sa_key', 'local_crypto_key', 'remote_crypto_key',
  'local_integr_key', 'remote_integr_key'
]);

/**
 * Decide if a key name refers to a sensitive value
 * @param {string} key - object key
 * @return {boolean}
 */
const isSensitiveKey = (key) => {
  if (typeof key !== 'string') return false;
  const k = key.toLowerCase();
  if (SENSITIVE_KEYS.has(k)) return true;
  // catch composite names such as userPassword, wifiPassword, ipsecPsk, vpnPrivateKey
  return /(password|passwd|secret|privatekey|private_key|psk$|[_-]key$|apikey|token$)/i.test(k) ||
    /^(ca|server|client|tls|dh|crypto|integr)key$/i.test(k);
};

/**
 * Return a deep copy of an object with the values of sensitive keys replaced.
 * Handles arrays, plain objects and circular references. Non plain objects
 * (Date, ObjectId, Buffer) are returned as their string representation.
 * @param {*} value - object to redact
 * @param {string} replacement - replacement value
 * @return {*} redacted copy
 */
const redactSecrets = (value, replacement = '***') => {
  const seen = new WeakMap();
  const walk = (v, depth) => {
    if (v === null || typeof v !== 'object') return v;
    if (depth > 32) return '[depth exceeded]';
    if (seen.has(v)) return '[circular]';
    if (Buffer.isBuffer(v)) return '[buffer]';
    if (typeof v.toJSON === 'function' && !Array.isArray(v)) {
      const j = v.toJSON();
      if (j === null || typeof j !== 'object') return j;
      v = j;
    }
    const out = Array.isArray(v) ? [] : {};
    seen.set(v, out);
    for (const k of Object.keys(v)) {
      if (!Array.isArray(v) && isSensitiveKey(k) && v[k] !== '' && v[k] != null) {
        out[k] = replacement;
      } else {
        out[k] = walk(v[k], depth + 1);
      }
    }
    return out;
  };
  return walk(value, 0);
};

/**
 * Parse IPv4 string to array of 4 numbers, or null
 */
const parseIPv4 = (ip) => {
  if (net.isIPv4(ip) === false) return null;
  return ip.split('.').map(Number);
};

/**
 * Expand IPv6 string to array of 8 16-bit numbers, or null
 */
const parseIPv6 = (ip) => {
  if (!net.isIPv6(ip)) return null;
  let addr = ip.split('%')[0]; // remove zone id
  // Handle embedded IPv4 (e.g. ::ffff:1.2.3.4)
  const v4Match = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Match) {
    const v4 = parseIPv4(v4Match[1]);
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    addr = addr.slice(0, addr.length - v4Match[1].length) + hi + ':' + lo;
  }
  const [head, tail] = addr.split('::');
  const headParts = head ? head.split(':') : [];
  const tailParts = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const missing = 8 - headParts.length - tailParts.length;
  if (addr.includes('::')) {
    if (missing < 0) return null;
  } else if (missing !== 0) return null;
  const parts = [...headParts, ...Array(addr.includes('::') ? missing : 0).fill('0'), ...tailParts];
  return parts.map(p => parseInt(p, 16));
};

/**
 * Check if an IP address is not a public unicast address (loopback, private,
 * link-local incl. cloud metadata, CGNAT, multicast, reserved, ...).
 * Invalid addresses are considered non-public.
 * @param {string} ip - IPv4 or IPv6 address
 * @return {boolean} true if the address must not be accessed by server-side requests
 */
const isPrivateAddress = (ip) => {
  const v4 = parseIPv4(ip);
  if (v4) {
    const [a, b, c] = v4;
    return a === 0 || // "this" network
      a === 10 || // private
      a === 127 || // loopback
      (a === 100 && b >= 64 && b <= 127) || // CGNAT
      (a === 169 && b === 254) || // link local / cloud metadata
      (a === 172 && b >= 16 && b <= 31) || // private
      (a === 192 && b === 0 && c === 0) || // IETF protocol assignments
      (a === 192 && b === 0 && c === 2) || // TEST-NET-1
      (a === 192 && b === 168) || // private
      (a === 198 && (b === 18 || b === 19)) || // benchmarking
      (a === 198 && b === 51 && c === 100) || // TEST-NET-2
      (a === 203 && b === 0 && c === 113) || // TEST-NET-3
      a >= 224; // multicast, reserved, broadcast
  }
  const v6 = parseIPv6(ip);
  if (!v6) return true;
  const isZeroPrefix = (n) => v6.slice(0, n).every(x => x === 0);
  // :: and ::1
  if (isZeroPrefix(7) && (v6[7] === 0 || v6[7] === 1)) return true;
  // IPv4 mapped ::ffff:a.b.c.d and IPv4 compatible ::a.b.c.d
  if (isZeroPrefix(5) && (v6[5] === 0xffff || v6[5] === 0)) {
    return isPrivateAddress(`${v6[6] >> 8}.${v6[6] & 0xff}.${v6[7] >> 8}.${v6[7] & 0xff}`);
  }
  // NAT64 64:ff9b::/96
  if (v6[0] === 0x64 && v6[1] === 0xff9b && v6.slice(2, 6).every(x => x === 0)) {
    return isPrivateAddress(`${v6[6] >> 8}.${v6[6] & 0xff}.${v6[7] >> 8}.${v6[7] & 0xff}`);
  }
  if ((v6[0] & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((v6[0] & 0xffc0) === 0xfe80) return true; // link local fe80::/10
  if ((v6[0] & 0xffc0) === 0xfec0) return true; // site local (deprecated)
  if ((v6[0] & 0xff00) === 0xff00) return true; // multicast
  if (v6[0] === 0x2001 && v6[1] === 0x0db8) return true; // documentation
  return false;
};

module.exports = {
  escapeRegExp,
  escapeHtml,
  findMongoOperatorKey,
  mongoSanitizer,
  isNonEmptyString,
  safeEqual,
  isSensitiveKey,
  redactSecrets,
  isPrivateAddress
};
