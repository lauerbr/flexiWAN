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

const Service = require('./Service');

const { getAccessKey } = require('../tokens');
const AccessTokens = require('../models/accesstokens');
const Organizations = require('../models/organizations');
const {
  preDefinedPermissions,
  validatePermissionCombination
} = require('../models/membership');

class AccessTokensService {
  /**
   * Get all AccessTokens
   *
   * offset Integer The number of items to skip before starting to collect the result set (optional)
   * limit Integer The numbers of items to return (optional)
   * returns List
   **/
  static async accesstokensGET ({ org, offset, limit }, { user }) {
    try {
      const response = await AccessTokens.find({ account: user.defaultAccount._id })
        .skip(offset)
        .limit(limit)
        .populate('organization');

      const result = response.map(record => {
        return {
          _id: record.id,
          name: record.name,
          token: record.token,
          isValid: record.isValid,
          group: record.group,
          organization: record?.organization?.name || null,
          to: record.to,
          role: record.role
        };
      });
      return Service.successResponse(result);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
   * Delete access token
   *
   * id String Numeric ID of the Access token to delete
   * no response value expected for this operation
   **/
  static async accesstokensIdDELETE ({ id }, { user }) {
    try {
      const { deletedCount } = await AccessTokens.deleteOne({
        _id: id,
        account: user.defaultAccount._id
      });

      if (deletedCount === 0) {
        return Service.rejectResponse('Access token not found', 404);
      }

      return Service.successResponse(null, 204);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }

  /**
   * Create new access token
   *
   * accessTokenRequest AccessTokenRequest  (optional)
   * returns AccessToken
   **/
  static async accesstokensPOST (accessTokenRequest, { user }) {
    try {
      // Check that required fields exist
      if (
        !user._id ||
        !user.defaultAccount ||
        !accessTokenRequest.accessKeyPermissionTo ||
        !accessTokenRequest.accessKeyRole ||
        !accessTokenRequest.accessKeyEntity
      ) {
        return Service.rejectResponse('Request does not have all necessary info', 400);
      };

      const permissionTo = accessTokenRequest.accessKeyPermissionTo;
      const role = accessTokenRequest.accessKeyRole;
      const entity = accessTokenRequest.accessKeyEntity;

      // Check permission combination
      const checkCombination = validatePermissionCombination(
        role,
        permissionTo
      );
      if (checkCombination.status === false) {
        return Service.rejectResponse(checkCombination.error, 400);
      }

      // This API is allowed only for account owner, so no need to check for permissions
      // But we need to make sure the entities are part of the account
      let inclusionChecker = { status: true, error: '' };
      switch (permissionTo) {
        case 'account':
          // check that entity equals to the account id
          if (user.defaultAccount._id.toString() !== entity) {
            inclusionChecker = { status: false, error: 'Invalid Account' };
          }
          break;
        case 'group': {
          // check that the group belongs to the account by checking that at least one of the
          // account organizations belong to the group entity
          const groupCount = await Organizations.count({
            _id: { $in: user.defaultAccount.organizations },
            group: entity
          });
          if (!groupCount) {
            inclusionChecker = { status: false, error: 'Invalid Group' };
          }
          break;
        }
        case 'organization':
          // check that the entity is part of the account organizations
          if (!user.defaultAccount.organizations.some((id) => id.toString() === entity)) {
            inclusionChecker = { status: false, error: 'Invalid Organization' };
          }
          break;
      }
      if (inclusionChecker.status === false) {
        return Service.rejectResponse(inclusionChecker.error, 400);
      }

      const accessToken = new AccessTokens({
        account: user.defaultAccount._id,
        to: permissionTo,
        group: permissionTo === 'group' ? entity : '',
        organization: permissionTo === 'organization' ? entity : null,
        role: role,
        // This api used as account owner only and user has permission to the entity (checked above)
        permissions: preDefinedPermissions[permissionTo + '_' + role],
        name: accessTokenRequest.name,
        token: '', // should be empty for now
        isValid: true
      });

      const token = await getAccessKey({ user }, {
        id: accessToken._id.toString()
      }, false);
      accessToken.token = token;

      await accessToken.save();

      return Service.successResponse({
        _id: accessToken.id,
        name: accessToken.name,
        token: accessToken.token
      }, 201);
    } catch (e) {
      return Service.rejectResponse(
        e.message || 'Internal Server Error',
        e.status || 500
      );
    }
  }
}

module.exports = AccessTokensService;
