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

const {
  escapeRegExp,
  escapeHtml,
  findMongoOperatorKey,
  mongoSanitizer,
  isNonEmptyString,
  safeEqual,
  redactSecrets,
  isPrivateAddress
} = require('../security');

describe('escapeRegExp', () => {
  it('matches special characters literally', () => {
    const input = 'a.b*c+d?e^f$g{h}i(j)k|l[m]n\\o/p-q';
    const re = new RegExp('^' + escapeRegExp(input) + '$');
    expect(re.test(input)).toBe(true);
    expect(re.test(input.replace('.', 'x'))).toBe(false);
  });

  it('neutralizes catastrophic backtracking patterns', () => {
    const re = new RegExp(escapeRegExp('(a+)+$'));
    const start = Date.now();
    expect(re.test('a'.repeat(50000) + '!')).toBe(false);
    expect(Date.now() - start).toBeLessThan(1000);
  });

  it('handles non string input', () => {
    expect(escapeRegExp(undefined)).toBe('');
    expect(escapeRegExp(12)).toBe('12');
  });
});

describe('escapeHtml', () => {
  it('escapes html special characters', () => {
    expect(escapeHtml('<a href="x" onclick=\'y\'>&</a>'))
      .toBe('&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  });
  it('handles null and numbers', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(5)).toBe('5');
  });
});

describe('findMongoOperatorKey / mongoSanitizer', () => {
  it('finds nested operator keys', () => {
    expect(findMongoOperatorKey({ a: 1, b: { c: [{ $ne: 1 }] } })).toBe('$ne');
    expect(findMongoOperatorKey({ id: { $exists: true } })).toBe('$exists');
  });

  it('accepts legitimate payloads', () => {
    expect(findMongoOperatorKey({
      email: 'a@b.com',
      'key.with.dots': 'x',
      filters: '[{"key":"name","op":"==","val":"$x"}]',
      list: [1, 'a$', { price$: 1 }]
    })).toBe(null);
    expect(findMongoOperatorKey('string')).toBe(null);
    expect(findMongoOperatorKey(undefined)).toBe(null);
  });

  it('rejects too deep objects', () => {
    let obj = {};
    const root = obj;
    for (let i = 0; i < 100; i++) {
      obj.a = {};
      obj = obj.a;
    }
    expect(findMongoOperatorKey(root)).not.toBe(null);
  });

  const runMiddleware = (req) => {
    const res = {
      statusCode: 200,
      body: null,
      status (code) { this.statusCode = code; return this; },
      type () { return this; },
      json (body) { this.body = body; return this; }
    };
    const next = jest.fn();
    mongoSanitizer(req, res, next);
    return { res, next };
  };

  it('middleware rejects operators in body', () => {
    const { res, next } = runMiddleware({
      body: { id: { $exists: true }, token: { $ne: 'x' } }, query: {}, params: {}
    });
    expect(res.statusCode).toBe(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('middleware rejects operators in query', () => {
    const { res, next } = runMiddleware({ body: {}, query: { email: { $gt: '' } }, params: {} });
    expect(res.statusCode).toBe(400);
    expect(next).not.toHaveBeenCalled();
  });

  it('middleware passes clean requests', () => {
    const { res, next } = runMiddleware({
      body: { email: ['a@b.com'], name: 'x' }, query: { org: '1' }, params: {}
    });
    expect(res.statusCode).toBe(200);
    expect(next).toHaveBeenCalled();
  });
});

describe('isNonEmptyString / safeEqual', () => {
  it('checks strings', () => {
    expect(isNonEmptyString('a')).toBe(true);
    expect(isNonEmptyString('')).toBe(false);
    expect(isNonEmptyString(['a'])).toBe(false);
    expect(isNonEmptyString({ $ne: 'x' })).toBe(false);
    expect(isNonEmptyString('abc', 2)).toBe(false);
  });
  it('compares strings', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', ['abc'])).toBe(false);
  });
});

describe('redactSecrets', () => {
  it('redacts nested sensitive keys and keeps the original object', () => {
    const input = {
      name: 'dev',
      password: 'p',
      nested: [{ psk: 'k', 'crypto-key': 'c', integr_key: 'i', ip: '1.1.1.1' }],
      bgp: { neighbors: [{ ip: '2.2.2.2', password: 'x' }] },
      vpn: { caKey: 'ca', serverKey: 's', privateKey: 'pk', port: 1194 },
      empty: { password: '' }
    };
    const out = redactSecrets(input);
    expect(out.name).toBe('dev');
    expect(out.password).toBe('***');
    expect(out.nested[0]).toEqual({
      psk: '***', 'crypto-key': '***', integr_key: '***', ip: '1.1.1.1'
    });
    expect(out.bgp.neighbors[0]).toEqual({ ip: '2.2.2.2', password: '***' });
    expect(out.vpn).toEqual({ caKey: '***', serverKey: '***', privateKey: '***', port: 1194 });
    expect(out.empty.password).toBe('');
    expect(input.password).toBe('p');
  });

  it('handles circular references and primitives', () => {
    const a = { x: 1 };
    a.self = a;
    expect(redactSecrets(a)).toEqual({ x: 1, self: '[circular]' });
    expect(redactSecrets('s')).toBe('s');
    expect(redactSecrets(null)).toBe(null);
  });
});

describe('isPrivateAddress', () => {
  it.each([
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:127.0.0.1',
    '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', 'not-an-ip'
  ])('%s is private', (ip) => {
    expect(isPrivateAddress(ip)).toBe(true);
  });

  it.each([
    '8.8.8.8', '1.1.1.1', '172.32.0.1', '192.169.0.1', '100.128.0.1',
    '2001:4860:4860::8888', '2606:4700:4700::1111', '::ffff:8.8.8.8'
  ])('%s is public', (ip) => {
    expect(isPrivateAddress(ip)).toBe(false);
  });
});
