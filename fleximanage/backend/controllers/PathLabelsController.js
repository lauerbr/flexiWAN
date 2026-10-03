const Controller = require('./Controller');

class PathLabelsController {
  constructor (Service) {
    this.service = Service;
  }

  async pathlabelsGET (request, response) {
    await Controller.handleRequest(request, response, this.service.pathlabelsGET);
  }

  async pathlabelsIdDELETE (request, response) {
    await Controller.handleRequest(request, response, this.service.pathlabelsIdDELETE);
  }

  async pathlabelsIdGET (request, response) {
    await Controller.handleRequest(request, response, this.service.pathlabelsIdGET);
  }

  async pathlabelsIdPUT (request, response) {
    await Controller.handleRequest(request, response, this.service.pathlabelsIdPUT);
  }

  async pathlabelsPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.pathlabelsPOST);
  }
}

module.exports = PathLabelsController;
