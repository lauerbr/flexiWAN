// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2020  flexiWAN Ltd.

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

const { Rules } = require('../appIdentifications');

let rule;

beforeEach(() => {
  // eslint-disable-next-line new-cap
  rule = new Rules({});
});

describe('Minimal required rule policy schema', () => {
  it('Should be a valid rule model if only ip is present', () => {
    rule.ip = '192.168.0.1/24';

    rule.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be a valid rule model if only ports is present', () => {
    rule.ports = '42';

    rule.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be a valid rule model if only ip and ports are present', () => {
    rule.ip = '192.168.0.1/24';
    rule.ports = '42';

    rule.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be a valid rule model if all fields are present', () => {
    rule.ip = '192.168.0.1/24';
    rule.ports = '42';
    rule.protocol = 'udp';

    rule.validate((err) => {
      expect(err).toBe(null);
    });
  });

  it('Should be invalid rule model if only protocol is present', () => {
    rule.protocol = 'udp';

    rule.validate((err) => {
      expect(err.message).toBe(
        'Rules validation failed: ip|ports: Either ip or ports field must not be empty'
      );
    });
  });
});

describe('Rules policy schema fields validation', () => {
  it('Should be an invalid rule model if ip is empty', () => {
    rule.ip = '';
    rule.ports = '42';

    rule.validate((err) => {
      expect(err.message).toBe(
        'Rules validation failed: ip: ip should be a valid ipv4 with mask type'
      );
    });
  });

  it('Should be an invalid rule model if ip has no mask', () => {
    rule.ip = '192.168.0.1';

    rule.validate((err) => {
      expect(err.message).toBe(
        'Rules validation failed: ip: ip should be a valid ipv4 with mask type'
      );
    });
  });

  it('Should be an invalid rule model if ip is IPv6', () => {
    rule.ip = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';

    rule.validate((err) => {
      expect(err.message).toBe(
        'Rules validation failed: ip: ip should be a valid ipv4 with mask type'
      );
    });
  });

  it('Should be an invalid rule model if ports is invalid', () => {
    rule.ip = '192.168.0.1/24';
    rule.ports = 'fourty two';

    rule.validate((err) => {
      expect(err.message).toBe(
        'Rules validation failed: ports: ports should be a valid ports range'
      );
    });
  });

  it('Should be invalid rule model if protocol has invalid value', () => {
    rule.ip = '192.168.0.1/24';
    rule.ports = '42';
    rule.protocol = 'gopher';

    rule.validate((err) => {
      expect(err.message).toBe(
        'Rules validation failed: protocol: ' +
          '`gopher` is not a valid enum value for path `protocol`.'
      );
    });
  });
});
