const Controller = require('./Controller');

class UsersController {
  constructor (Service) {
    this.service = Service;
  }

  async usersLoginPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.usersLoginPOST);
  }

  async usersResetPasswordPOST (request, response) {
    await Controller.handleRequest(request, response, this.service.usersResetPasswordPOST);
  }
}

module.exports = UsersController;
