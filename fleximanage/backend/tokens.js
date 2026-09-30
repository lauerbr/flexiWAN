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

var jwt = require('jsonwebtoken');
const { preDefinedPermissions, getUserPermissions } = require('./models/membership');
var configs = require('./configs')();
const logger = require('./logging/logging')({ module: module.filename, type: 'req' });

// JWT strategy definition
// Generate token
exports.getToken = async function ({ user }, override = {}, shouldExpire = true) {
  // Get user permissions
  let perms = null;
  try {
    perms = await getUserPermissions(user);
  } catch (err) {
    perms = { ...preDefinedPermissions.none };
    logger.error('Could not get user permissions', {
      params: { user: user, message: err.message }
    });
  }

  // if not specifics in "override", use it from previous jwt if exists
  const mfaVerified = user.isLoggedInWithMfa ?? false;

  return jwt.sign(
    {
      _id: user._id,
      username: user.username,
      org: user.defaultOrg ? user.defaultOrg._id : null,
      orgName: user.defaultOrg ? user.defaultOrg.name : null,
      account: user.defaultAccount ? user.defaultAccount._id : null,
      accountName: user.defaultAccount
        ? user.defaultAccount.name
        : null,
      perms: perms,
      mfaVerified,
      ...override
    },
    configs.get('userTokenSecretKey'),
    shouldExpire ? { expiresIn: configs.get('userTokenExpiration', 'number') } : null
  );
};

exports.getAccessKey = async ({ user }, override = {}, shouldExpire = true) => {
  return jwt.sign(
    {
      _id: user._id,
      type: 'app_access_key',
      account: user.defaultAccount ? user.defaultAccount._id : null,
      ...override
    },
    configs.get('userTokenSecretKey'),
    shouldExpire ? { expiresIn: configs.get('userTokenExpiration', 'number') } : null
  );
};

exports.getRefreshToken = async ({ user }, override = {}) => {
  return jwt.sign({
    _id: user._id,
    username: user.username,
    ...override,
    // Mark the token as a refresh token, only such tokens are accepted for refresh
    type: 'refresh',
    // Refresh tokens are revoked by incrementing the user token version
    tokenVersion: user.tokenVersion ?? 0
  }, configs.get('userTokenSecretKey'), {
    expiresIn: configs.get('userRefreshTokenExpiration', 'number')
  });
};

exports.verifyToken = (token) => {
  return jwt.verify(token, configs.get('userTokenSecretKey'));
};

/**
 * Check if a decoded token payload is a refresh token.
 * Refresh tokens issued before the 'refresh' type was introduced have no type,
 * no permissions and no account, which distinguishes them from access tokens,
 * access keys and login tokens.
 * @param {Object} payload - decoded and verified JWT payload
 * @return {boolean}
 */
exports.isRefreshTokenPayload = (payload) => {
  if (!payload || typeof payload !== 'object') return false;
  if (payload.type === 'refresh') return true;
  return payload.type === undefined && payload.perms === undefined &&
    payload.account === undefined && payload.org === undefined &&
    typeof payload._id === 'string';
};

exports.getLoginProcessToken = async (user) => {
  return jwt.sign(
    {
      type: 'login',
      userId: user._id,
      mfaEnabled: user?.mfa?.enabled ?? false
    },
    configs.get('userTokenSecretKey'),
    { expiresIn: 180 } // 3 minutes to complete login process
  );
};
