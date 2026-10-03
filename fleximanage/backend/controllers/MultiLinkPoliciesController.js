const Controller = require('./Controller');

class MultiLinkPoliciesController {
  constructor (Service) {
    this.service = Service;
  }

  async mlpoliciesGET (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesGET);
  }

  async mlpoliciesIdDELETE (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesIdDELETE);
  }

  async mlpoliciesIdGET (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesIdGET);
  }

  async mlpoliciesIdPUT (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesIdPUT);
  }

  async mlpoliciesListGET (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesListGET);
  }

  async mlpoliciesPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesPOST);
  }

  async mlpoliciesMetaGET (request, response) {
    await Controller.handleRequest(request, response, this.service.mlpoliciesMetaGET);
  }
}

module.exports = MultiLinkPoliciesController;
