// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2023  flexiWAN Ltd.

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

// Module for membershipUtils Unit Test
/* eslint-disable max-len */
const membershipUtils = require('../membershipUtils');
const ObjectId = require('mongoose').Types.ObjectId;
const organizations = require('../../models/organizations');
const { membership } = require('../../models/membership');

let organizationResponse = [];
let membershipResponse = [];
let expectedOrganizationQuery = {};
let expectedMembershipQuery = {};
let userParams = {};

const setOrganizationQuery = (query, response) => {
  expectedOrganizationQuery = query;
  organizationResponse = response;
};
const setMembershipQuery = (query, response) => {
  expectedMembershipQuery = query;
  membershipResponse = response;
};

beforeAll(async () => {
  // Override organizations find
  delete organizations.find;
  organizations.find = function (query, project) {
    expect(query).toEqual(expectedOrganizationQuery);
    return organizationResponse;
  };
  module.exports = organizations;
  setOrganizationQuery({
    _id: {
      $in: [ObjectId('5ef0b7a657344d1ad6187100'),
        ObjectId('5ef0b7a657344d1ad6187101'),
        ObjectId('5ef0b7a657344d1ad6187102')]
    },
    group: 'Default'
  }, [
    ObjectId('5ef0b7a657344d1ad6187100'), ObjectId('5ef0b7a657344d1ad6187101')
  ]);
  // Override membership find
  delete membership.find;
  membership.find = function (query, project) {
    expect(query).toEqual(expectedMembershipQuery);
    return membershipResponse;
  };
  module.exports = membership;
  setMembershipQuery({
    user: ObjectId('5deaeae628e84b2bac6a5000'),
    account: ObjectId('5deaeae628e84b2bac6a4000')
  }, [{
    to: 'account',
    group: '',
    organization: null,
    role: 'viewer'
  }]);
  // eslint-disable-next-line no-extend-native
  Array.prototype.lean = function () { return this; };
});

describe('Access Token Test', () => {
  beforeEach(() => {
    userParams = {
      accessToken: true,
      tokenTo: 'group',
      tokenGroup: 'Default',
      tokenOrganization: null,
      role: 'viewer',
      defaultAccount: {
        _id: ObjectId('5deaeae628e84b2bac6a4000'),
        organizations: [
          ObjectId('5ef0b7a657344d1ad6187100'),
          ObjectId('5ef0b7a657344d1ad6187101'),
          ObjectId('5ef0b7a657344d1ad6187102')
        ]
      }
    };
  });

  it('OrgId required is not allowed with group (orgId set, modify=true)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, 'Default', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with group (orgId set, modify=false)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with group (orgId not set, modify=true)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, null, 'Default', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with group (orgId not set, modify=false)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, null, 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with account (orgId set, modify=true)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, '5deaeae628e84b2bac6a4000', '', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with account (orgId set, modify=false)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, '5deaeae628e84b2bac6a4000', '', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with account (orgId not set, modify=true)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, '5deaeae628e84b2bac6a4000', '', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('OrgId required is not allowed with account (orgId not set, modify=false)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, '5deaeae628e84b2bac6a4000', '', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization ID required and multi organization operation is not allowed'));
    done();
  });

  it('Only one orgId, group, account allowed (orgId+account)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', false, '5deaeae628e84b2bac6a4000', '', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Multiple organization definitions are not allowed'));
    done();
  });

  it('Only one orgId, group, account allowed (orgId+group)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', false, null, 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Multiple organization definitions are not allowed'));
    done();
  });

  it('Only one orgId, group, account allowed (group+account)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, '5deaeae628e84b2bac6a4000', 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Multiple organization definitions are not allowed'));
    done();
  });

  it('Only one orgId, group, account allowed (orgId+group+account)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', false, '5deaeae628e84b2bac6a4000', 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Multiple organization definitions are not allowed'));
    done();
  });

  it('When modifying, an entity to modify must be specified', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Modification with no entity is not allowed'));
    done();
  });

  it('AccessToken with org required without orgId is not allowed (modify=true)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization query parameter must be specified for this operation'));
    done();
  });

  it('AccessToken with org required without orgId is not allowed (modify=false)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization query parameter must be specified for this operation'));
    done();
  });

  it('orgId set, org required (modify=true, org in account, permission=viewer)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'viewer';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([]);
    expect(err).toEqual(undefined);
    done();
  });

  it('orgId set, org required (modify=true, org in account, permission=manager)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'manager';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('orgId set, org required (modify=true, org in account, permission=owner)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'owner';
      userParams.tokenTo = 'account';
      userParams.tokenGroup = '';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('orgId set, org required (modify=false, org in account, permission=viewer)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'viewer';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('orgId set, org required (modify=false, org in account, permission=manager)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'manager';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('orgId set, org required (modify=false, org in account, permission=owner)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'owner';
      userParams.tokenTo = 'account';
      userParams.tokenGroup = '';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('orgId set, org required (modify=false, org not in account)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'viewer';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187500', true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([]);
    expect(err).toEqual(undefined);
    done();
  });

  it('Default: orgId not set, org not required, no group/account, modify=false (permission=account owner)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'owner';
      userParams.tokenTo = 'account';
      userParams.tokenGroup = '';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([
      '5ef0b7a657344d1ad6187100',
      '5ef0b7a657344d1ad6187101',
      '5ef0b7a657344d1ad6187102']);
    expect(err).toEqual(undefined);
    done();
  });

  it('Default: orgId not set, org not required, no group/account, modify=false (permission=account viewer)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'viewer';
      userParams.tokenTo = 'account';
      userParams.tokenGroup = '';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([
      '5ef0b7a657344d1ad6187100',
      '5ef0b7a657344d1ad6187101',
      '5ef0b7a657344d1ad6187102']);
    expect(err).toEqual(undefined);
    done();
  });

  it('Default: orgId not set, org not required, no group/account, modify=false (permission=group viewer)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([
      '5ef0b7a657344d1ad6187100',
      '5ef0b7a657344d1ad6187101']);
    expect(err).toEqual(undefined);
    done();
  });

  it('Default: orgId not set, org not required, no group/account, modify=false (permission=org mgr)', async (done) => {
    let err, orgs;
    try {
      userParams.role = 'manager';
      userParams.tokenTo = 'organization';
      userParams.tokenOrganization = '5ef0b7a657344d1ad6187101';
      userParams.tokenGroup = '';
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187101']);
    expect(err).toEqual(undefined);
    done();
  });

  it('org not required, org set, modify=false (permission=group viewer)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187101', false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187101']);
    expect(err).toEqual(undefined);
    done();
  });

  it('org not required, group set, modify=false (permission=group viewer)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100', '5ef0b7a657344d1ad6187101']);
    expect(err).toEqual(undefined);
    done();
  });

  it('org not required, account set, modify=false (permission=group viewer)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, '5deaeae628e84b2bac6a4000', '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([]); // group viewer cannot access all account orgs, therefore fail
    expect(err).toEqual(undefined);
    done();
  });
});

describe('User Token Test', () => {
  beforeEach(() => {
    userParams = {
      _id: ObjectId('5deaeae628e84b2bac6a5000'),
      accessToken: false,
      defaultOrg: {
        _id: ObjectId('5ef0b7a657344d1ad6187100')
      },
      defaultAccount: {
        _id: ObjectId('5deaeae628e84b2bac6a4000'),
        organizations: [
          ObjectId('5ef0b7a657344d1ad6187100'),
          ObjectId('5ef0b7a657344d1ad6187101'),
          ObjectId('5ef0b7a657344d1ad6187102')
        ]
      }
    };
  });

  it('Org required with orgId returns not allowed (modify=true)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization query parameter is only available in Access Key'));
    done();
  });

  it('Org required with orgId returns not allowed (modify=false)', async (done) => {
    let err;
    try {
      await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(err).toEqual(new Error('Organization query parameter is only available in Access Key'));
    done();
  });

  it('Org required without orgId returns the user org (modify=true)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('Org required without orgId returns the user org (modify=false)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, true, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('Default: orgId not set, org not required, no group/account, modify=false', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('org not required, org set, modify=false (permission=account viewer)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', false, null, '', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100']);
    expect(err).toEqual(undefined);
    done();
  });

  it('org not required, org set, modify=true (permission=account viewer)', async (done) => {
    let err, orgs;
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        '5ef0b7a657344d1ad6187100', false, null, '', true);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual([]);
    expect(err).toEqual(undefined);
    done();
  });

  it('org not required, group set, modify=false (sum orgs in group)', async (done) => {
    let err, orgs;
    setMembershipQuery({
      user: ObjectId('5deaeae628e84b2bac6a5000'),
      account: ObjectId('5deaeae628e84b2bac6a4000')
    }, [{
      to: 'organization',
      group: '',
      organization: ObjectId('5ef0b7a657344d1ad6187100'),
      role: 'viewer'
    }, {
      to: 'organization',
      group: '',
      organization: ObjectId('5ef0b7a657344d1ad6187101'),
      role: 'viewer'
    }]);
    try {
      orgs = await membershipUtils.getAccessTokenOrgList(userParams,
        null, false, null, 'Default', false);
    } catch (e) {
      err = e;
    }
    expect(orgs).toEqual(['5ef0b7a657344d1ad6187100', '5ef0b7a657344d1ad6187101']);
    expect(err).toEqual(undefined);
    done();
  });
});
