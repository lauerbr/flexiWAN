class Service {
  static rejectResponse (error, code = 500, data = {}) {
    return { error, code, data };
  }

  static successResponse (payload, code = 200) {
    return { payload, code };
  }
}

module.exports = Service;
