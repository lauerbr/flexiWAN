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

const Controller = require('./Controller');

class AccessTokensController {
  constructor (Service) {
    this.service = Service;
  }

  async accesstokensGET (request, response) {
    await Controller.handleRequest(request, response, this.service.accesstokensGET);
  }

  async accesstokensIdDELETE (request, response) {
    await Controller.handleRequest(request, response, this.service.accesstokensIdDELETE);
  }

  async accesstokensPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.accesstokensPOST);
  }
}

module.exports = AccessTokensController;
