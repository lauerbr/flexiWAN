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

const organizations = require('../models/organizations');
const User = require('../models/users');
const { membership } = require('../models/membership');
const { getToken } = require('../tokens');
const difference = require('lodash/difference');
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });

/**
 * Fetch all organizations accessible by a user.
 * The accountId should be provided when the user isn't the one currently logged in.
 * @param {Object} user - user DB object
 * @param {Integer} offset The number of items to skip (optional)
 * @param {Integer} limit The numbers of items to return (optional)
 * @param {String} accountId account identifier (optional)
 */
const getUserOrganizations = async (user, offset = 0, limit = 0, accountId = null) => {
  if ((!accountId && !user?.defaultAccount?._id) || !user._id) return [];

  /* Organizations permitted are:
       - If user has account permissions, get all account organizations
       - If user has group permissions, get all accounts for this group
       - Get all organizations permitted for user
    */

  try {
    const resultSet = {};

    // If user has account permissions, get all account organizations
    const account = await membership.findOne({
      user: user._id,
      account: accountId || user.defaultAccount._id,
      to: 'account'
    });
    if (account) {
      const accountOrgs = await organizations.find({
        account: accountId || user.defaultAccount._id
      }).skip(offset).limit(limit);
      accountOrgs.forEach((entry) => { resultSet[entry._id] = entry; });
    }

    // If user has group permissions, get all accounts for this group
    const groups = await membership.distinct('group', {
      user: user._id,
      account: accountId || user.defaultAccount._id,
      to: 'group'
    });
    const groupOrgs = await organizations.find({
      account: accountId || user.defaultAccount._id,
      group: { $in: groups }
    }).skip(offset).limit(limit);
    groupOrgs.forEach((entry) => { resultSet[entry._id] = entry; });

    // Add all organizations permitted for user
    const orgs = await membership.find({
      user: user._id,
      account: accountId || user.defaultAccount._id,
      to: 'organization'
    })
      .populate('organization');
    orgs.forEach((org) => { resultSet[org.organization._id] = org.organization; });
    return resultSet;
  } catch (err) {
    logger.error('Error getting user organizations', { params: { reason: err.message } });
  }

  return [];
};

/**
 * Get user organization by organization id
 * @param {Object} user  - request user
 * @param {String} orgId
 */
const getUserOrgByID = async (user, orgId) => {
  try {
    // Find org with the correct ID
    const orgs = await getUserOrganizations(user);
    const resultOrg = (orgs[orgId]) ? [orgs[orgId]] : [];
    return resultOrg;
  } catch (err) {
    logger.error('Error getting organization', { params: { reason: err.message } });
    throw new Error('Error getting organization');
  }
};

/** validateOrgAccess
 *  Check if user is allowed to access the orgs specified for view or modify
 *  User (or access token) has permissions, check if they are sufficient to access
 */
const validateOrgAccess = async (user, to = 'organization', entity = null, modify = false) => {
  if (entity === null) throw new Error('Access entity is not specified');
  // get all permissions for the user
  let userPermissions = [];
  if (user.accessToken) {
    userPermissions.push({
      to: user.tokenTo,
      group: user.tokenGroup,
      organization: user.tokenOrganization,
      role: user.role
    });
  } else {
    userPermissions = await membership.find({ account: user.defaultAccount._id, user: user._id },
      { to: 1, group: 1, organization: 1, role: 1, _id: 0 }).lean();
  }

  const roles = ['manager', 'owner']; // roles for any modify value
  if (!modify) roles.push('viewer'); // if view operation, we can add viewer permission
  // Start with the simple and more common options:
  // If user has an account permission, or exact permission,
  // he can access all entities under it
  const foundPermission = userPermissions.find((permission) => {
    const permissionEntity = permission.to === 'organization' ? permission.organization
      : permission.to === 'group' ? permission.group
        : user.defaultAccount._id;
    if ((permission.to === 'account' || (permission.to === to && permissionEntity === entity)) &&
    roles.includes(permission.role)) return true;
    return false;
  });

  // Find the organizations for permission
  const getPermissionOrganizations = async (permission) => {
    switch (permission.to) {
      case 'account':
        // Get all organizations under the account
        if (user.defaultAccount._id.toString() === permission.entity) {
          return user.defaultAccount?.organizations.map(o => o._id.toString()) ?? [];
        } else {
          return [];
        }
      case 'group': {
        // Get all organizations for this group
        const orgs = await organizations.find({
          _id: { $in: user.defaultAccount?.organizations ?? [] },
          group: permission.entity
        }, { _id: 1 });
        return orgs.map(o => o._id.toString());
      }
      case 'organization':
        // Reply with the organization
        if (user.defaultAccount.organizations.some((id) => id.toString() === permission.entity)) {
          return [permission.entity];
        } else {
          return [];
        }
    }
  };

  const organizationsToAccess = await getPermissionOrganizations({ to, entity });
  if (foundPermission) { // return the organizations for the requested permission
    return organizationsToAccess;
  }
  // The more complex case, requires mix and match across all permissions
  // Since user can have for example permission to multiple individual orgs
  // so he can also access the group composed of all these orgs
  // Loop through all permissions and make sure all require access orgs are permitted
  let leftOrganizations = [...organizationsToAccess];
  for (const permission of userPermissions) {
    if (roles.includes(permission.role)) {
      permission.entity = permission.to === 'organization' ? permission.organization.toString()
        : permission.to === 'group' ? permission.group : user.defaultAccount._id;
      const allowedOrganizations = await getPermissionOrganizations(permission);
      leftOrganizations = difference(leftOrganizations, allowedOrganizations);
    }
    // If the list is empty we can skip the rest of the permissions
    if (leftOrganizations.length === 0) return organizationsToAccess;
  }
  // If we reached this place, organizations we want to access not satisfied
  // return empty list
  return [];
};

/**
 * Get Account Organization List when Access Token is used
 * If no Access Token is used, return the default organization
 * Otherwise, if no orgID is specified, return a list of all account organizations
 * If orgId is specified, return this orgID if exist in the account organizations
 *
 * @param {Object} user - request user
 * @param {String} orgId
 * @param {Boolean} orgIdRequired - whether org must be specified for the operation
 * @param {String} accountId - if access to the account is required
 * @param {String} group - if access to specific group is required
 * @param {Boolean} isModify - if the operation is for view (false) or modification (true)
 * @returns {List} List of organizations (as strings)
 */
const getAccessTokenOrgList = async (
  user, orgId, orgIdRequired = false, accountId = null, group = '', isModify = false) => {
  /*
   * If orgIdRequired, a single organization must be specified - taken from the query or user
   * Otherwise multiple organization can be accessed.
   * In the standard case, user view information from multiple organizations under the
   * account or group and isModify = false
   * There are cases where user wants to modify multiple organizations. An example is
   * on notification changes where user wants to modify the settings for all organizations
   * or group in that case isModify should be true
   * More info in the following table:
   *  orgId     orgIdRequired   accountId/group   isModify      result
   *  -------   -------------   ---------------   -----------   -----------
   *  set       true            set               true          not allowed (1)
   *                                                            orgID required + account/group
   *  set       true            set               false         not allowed (1)
   *  not set   true            set               true          not allowed (1)
   *  not set   true            set               false         not allowed (1)
   *  set       false           set               true          not allowed (2)
   *                                                            When orgId is not required
   *                                                            only one orgId/accountId/group
   *                                                            is allowed
   *  set       false           set               false         not allowed (2)
   *  not set   false           not set           true          not allowed (3)
   *  not set   true            not set           true          for UI token, return user org (5)
   *                                                            for access token, not allowed (4)
   *  not set   true            not set           false         for UI token, return user org (5)
   *                                                            for access token, not allowed (4)
   *  set       true            not set           true          for UI token, not allowed (6)
   *                                                            for access token, return org after
   *                                                            validation
   *  set       true            not set           false         for UI token, not allowed (6)
   *                                                            for access token return org after
   *                                                            validation
   *  not set   false           not set           false         Default case: for UI token,
   *                                                            return user org
   *                                                            for access-token, return all
   *                                                            organizations under the token entity
   *  not set   false           set               true          Return all organizations in the
   *                                                            account/group with modify permission
   *  not set   false           set               false         Return all organizations in the
   *                                                            account/group with view permission
   *  set       false           not set           true          return org with modify permission
   *                                                            after validation
   *  set       false           not set           false         return org with view permission
   *                                                            after validation
   *
   *
   */
  // 1. It's not allowed to set orgIdRequired and accountId/group who require multiple organizations
  if (orgIdRequired && (accountId || group)) {
    throw new Error('Organization ID required and multi organization operation is not allowed');
  }
  // 2. only one group is allowed, if empty query is in the account level
  const groups = [orgId, accountId, group].filter(g => g);
  if (groups.length > 1) {
    throw new Error('Multiple organization definitions are not allowed');
  }
  // 3. When modifying, an entity must be specified
  if (groups.length === 0 && !orgIdRequired && isModify) {
    throw new Error('Modification with no entity is not allowed');
  }

  if (orgIdRequired) {
    if (user.accessToken) {
      if (!orgId) {
        // 4. Access token where org is required for the operation, must be specified
        throw new Error('Organization query parameter must be specified for this operation');
      } else {
        // return org after validation for modify/view
        return await validateOrgAccess(user, 'organization', orgId, isModify);
      }
    } else {
      if (!orgId) {
        // 5. No access token return user orgId if no orgId found
        return [user.defaultOrg._id.toString()];
      } else {
        // 6. For UI token, orgId must not be specified when orgRequired
        throw new Error('Organization query parameter is only available in Access Key');
      }
    }
  } else {
    if (groups.length === 0) {
      // Default case
      if (!user.accessToken) return [user.defaultOrg._id.toString()];
      const orgs = await validateOrgAccess(user, user.tokenTo,
        user.tokenTo === 'organization' ? user.tokenOrganization
          : user.tokenTo === 'group' ? user.tokenGroup
            : user.defaultAccount._id.toString(), false);
      return orgs;
    } else {
      let orgs;
      if (accountId) {
        orgs = await validateOrgAccess(user, 'account', accountId, isModify);
      } else if (group) {
        orgs = await validateOrgAccess(user, 'group', group, isModify);
      } else {
        orgs = await validateOrgAccess(user, 'organization', orgId, isModify);
      }
      return orgs;
    }
  }
  // Should not reach this place
};

/**
 * Get all accounts available for a user
 * @param {Object} user - user object with user _id
 * @param {Integer} offset The number of items to skip (optional)
 * @param {Integer} limit The numbers of items to return (optional)
 */
const getUserAccounts = async (user, offset = 0, limit = 0) => {
  if (!user._id) return [];

  const resultSet = {};
  try {
    // Add all accounts user has access to
    const accounts = await membership.find({
      user: user._id
    })
      .skip(offset)
      .limit(limit)
      .populate('account');
    accounts.forEach((entry) => {
      resultSet[entry.account._id] = {
        name: entry.account.name,
        forceMfa: entry.account?.forceMfa
      };
    });
    const result = Object.keys(resultSet).map(key => {
      return { _id: key, name: resultSet[key].name, forceMfa: resultSet[key].forceMfa };
    });
    return result;
  } catch (err) {
    logger.error('Error getting user accounts', { params: { reason: err.message } });
  }
  return [];
};

/**
 * Update default organization when it's null and refresh token
 * If defaultOrg is null, will to find a new organization and update the req with it
 * @param {*} req - req with updated user account info
 * @param {*} res - res with updated token if necessary
 */
const orgUpdateFromNull = async ({ user }, res) => {
  if (user.defaultOrg == null) {
    let org0 = null;

    // Check if account is set, if not try to set one for the user
    if (user._id && !user.defaultAccount) {
      const account = await membership.findOne({ user: user._id }).populate('account');
      if (account) {
        user.defaultAccount = account.account;
        await User.updateOne({ _id: user._id }, { defaultAccount: account.account._id });
      }
    }

    try {
      const orgs = await getUserOrganizations(user);
      org0 = orgs[Object.keys(orgs)[0]];
      if (org0) {
        await User.updateOne({ _id: user._id }, { defaultOrg: org0._id });
        user.defaultOrg = org0;
      }
      // Refresh JWT with new values
      const token = await getToken({ user }, {
        account: user.defaultAccount._id,
        accountName: user.defaultAccount.name,
        org: org0 ? org0._id : null,
        orgName: org0 ? org0.name : null
      });
      res.setHeader('Refresh-JWT', token);
    } catch (err) {
      logger.error('Could not update organization',
        { params: { userId: user._id, message: err.message } });
      return false;
    }
  }
  return true;
};

// /**
//  * Update default organization when it's null and refresh token
//  * If defaultOrg is null, will to find a new organization and update the req with it
//  * @param {*} req - req with updated user account info
//  * @param {*} res - res with updated token if necessary
//  */
// const orgUpdateFromNull = async (req, res) => {
//   if (req.user.defaultOrg == null) {
//     let org0 = null;
//     try {
//       const orgs = await getUserOrganizations(req.user);
//       org0 = orgs[Object.keys(orgs)[0]];
//       if (org0) {
//         await User.updateOne({ _id: req.user._id }, { defaultOrg: org0._id });
//         req.user.defaultOrg = org0;
//       }
//       // Refresh JWT with new values
//       const token = await getToken(req, {
//         account: req.user.defaultAccount._id,
//         accountName: req.user.defaultAccount.name,
//         org: org0 ? org0._id : null,
//         orgName: org0 ? org0.name : null
//       });
//       res.setHeader('Refresh-JWT', token);
//     } catch (err) {
//       logger.error('Could not update organization',
//         { params: { userId: req.user._id, message: err.message }, req: req });
//       return false;
//     }
//   }
//   return true;
// };

// Default exports
module.exports = {
  getUserOrganizations: getUserOrganizations,
  getUserOrgByID: getUserOrgByID,
  getAccessTokenOrgList: getAccessTokenOrgList,
  getUserAccounts: getUserAccounts,
  orgUpdateFromNull: orgUpdateFromNull
};
