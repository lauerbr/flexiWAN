const Controller = require('./Controller');

class TokensController {
  constructor (Service) {
    this.service = Service;
  }

  async tokensGET (request, response) {
    await Controller.handleRequest(request, response, this.service.tokensGET);
  }

  async tokensIdDELETE (request, response) {
    await Controller.handleRequest(request, response, this.service.tokensIdDELETE);
  }

  async tokensIdGET (request, response) {
    await Controller.handleRequest(request, response, this.service.tokensIdGET);
  }

  async tokensIdPUT (request, response) {
    await Controller.handleRequest(request, response, this.service.tokensIdPUT);
  }

  async tokensPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.tokensPOST);
  }
}

module.exports = TokensController;
