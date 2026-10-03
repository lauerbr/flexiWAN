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

const Controller = require('./Controller');

class VrrpController {
  constructor (Service) {
    this.service = Service;
  }

  async vrrpGET (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpGET);
  }

  async vrrpPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpPOST);
  }

  async vrrpIdDELETE (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpIdDELETE);
  }

  async vrrpIdGET (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpIdGET);
  }

  async vrrpIdPUT (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpIdPUT);
  }

  async vrrpDeviceVrrpInterfacesGET (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpDeviceVrrpInterfacesGET);
  }

  async vrrpStatusGET (request, response) {
    await Controller.handleRequest(request, response, this.service.vrrpStatusGET);
  }
}

module.exports = VrrpController;
