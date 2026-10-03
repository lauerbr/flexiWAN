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

const errorCodes = {
  LAN_OVERLAPPING: 'LAN_OVERLAPPING',
  TUNNEL_OVERLAPPING: 'TUNNEL_OVERLAPPING',
  APPLICATION_OVERLAPPING: 'APPLICATION_OVERLAPPING',
  VRRP_INSTALLED_ON_DEVICE: 'VRRP_INSTALLED_ON_DEVICE'
};

module.exports = errorCodes;
