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
const configs = require('../configs')();
const url = require('url');

const getUiServerUrl = req => {
  let uiServerUrl = null;
  const uiServers = configs.get('uiServerUrl', 'list');
  let refererHeader = req.get('Referer');
  if (refererHeader) {
    refererHeader = refererHeader.slice(0, -1); // no need the slash at end
    const found = uiServers.find(s => s === refererHeader);
    if (found) {
      uiServerUrl = refererHeader;
    } else {
      uiServerUrl = uiServers[0];
    }
  } else {
    uiServerUrl = uiServers[0];
  }
  return uiServerUrl;
};

const getAgentBroker = tokenServer => {
  const brokerServers = configs.get('agentBroker', 'list');
  let broker = brokerServers[0];
  if (tokenServer) {
    // Try to find broker with the same domain as the token
    // If not found return the first agent broker
    const urlSchema = new url.URL(tokenServer);
    const tokenDomain = urlSchema.hostname.replace(/^[^.]+\./g, '');
    brokerServers.forEach(s => {
      const sUrlSchema = new url.URL('http://' + s);
      const sDomain = sUrlSchema.hostname.replace(/^[^.]+\./g, '');
      if (sDomain === tokenDomain) broker = s;
    });
  }
  return broker;
};

const getRedisAuthUrl = redisUrl => {
  const urlInfo = new URL(redisUrl);
  const redisAuth = urlInfo.username;
  urlInfo.username = '';
  const redisUrlNoAuth = urlInfo.href;
  return { redisAuth, redisUrlNoAuth };
};

module.exports = {
  getUiServerUrl,
  getAgentBroker,
  getRedisAuthUrl
};
