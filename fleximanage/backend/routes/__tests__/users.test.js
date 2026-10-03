// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019-2025  flexiWAN Ltd.

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

// Input validation tests of the unauthenticated users routes
const http = require('http');
const express = require('express');
const User = require('../../models/users');
const mailer = require('../../utils/mailer')();
const usersRouter = require('../users');

let server;
let baseUrl;

const post = (path, body) => {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(baseUrl + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    }, (res) => {
      let resBody = '';
      res.on('data', chunk => { resBody += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: resBody }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
};

beforeAll((done) => {
  const app = express();
  app.use('/api/users', usersRouter);
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ error: err.message });
  });
  server = app.listen(0, '127.0.0.1', () => {
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    done();
  });
});

afterAll((done) => {
  server.close(done);
});

let findOneAndUpdate;
let sendMail;
beforeEach(() => {
  findOneAndUpdate = jest.spyOn(User, 'findOneAndUpdate');
  sendMail = jest.spyOn(mailer, 'sendMailHTML').mockImplementation(() => Promise.resolve());
});
afterEach(() => {
  jest.restoreAllMocks();
});

describe('reset password', () => {
  it('rejects an array of e-mails', async () => {
    const res = await post('/api/users/reset-password', {
      type: 'reset', email: ['victim@example.com', 'attacker@example.com']
    });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).not.toHaveBeenCalled();
    expect(sendMail).not.toHaveBeenCalled();
  });

  it('rejects an operator object as e-mail', async () => {
    const res = await post('/api/users/reset-password', {
      type: 'reset', email: { $ne: 'x' }
    });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).not.toHaveBeenCalled();
  });

  it('sends the mail only to the stored address and sets an expiration', async () => {
    findOneAndUpdate.mockImplementation(() =>
      Promise.resolve({ _id: '5deaeae628e84b2bac6a5000', email: 'stored@example.com' }));
    const res = await post('/api/users/reset-password', {
      type: 'reset', email: 'Stored@Example.com'
    });
    expect(res.status).toBe(200);
    expect(findOneAndUpdate).toHaveBeenCalledTimes(1);
    const update = findOneAndUpdate.mock.calls[0][1];
    expect(update['emailTokens.resetPasswordExpires'].getTime()).toBeGreaterThan(Date.now());
    expect(sendMail).toHaveBeenCalledTimes(1);
    expect(sendMail.mock.calls[0][2]).toBe('stored@example.com');
  });
});

describe('update password', () => {
  it('rejects operator objects as id and token', async () => {
    const res = await post('/api/users/reset-password', {
      type: 'update', id: { $exists: true }, token: { $ne: 'x' }, password: 'newpassword1'
    });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).not.toHaveBeenCalled();
  });

  it('rejects an invalid object id', async () => {
    const res = await post('/api/users/reset-password', {
      type: 'update', id: 'abc', token: 'token', password: 'newpassword1'
    });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).not.toHaveBeenCalled();
  });

  it('checks token expiration and revokes refresh tokens', async () => {
    findOneAndUpdate.mockImplementation(() => Promise.resolve(null));
    const res = await post('/api/users/reset-password', {
      type: 'update', id: '5deaeae628e84b2bac6a5000', token: 'abc', password: 'newpassword1'
    });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).toHaveBeenCalledTimes(1);
    const [query, update] = findOneAndUpdate.mock.calls[0];
    expect(query._id).toBe('5deaeae628e84b2bac6a5000');
    expect(query['emailTokens.resetPassword']).toBe('abc');
    expect(query.$or[0]['emailTokens.resetPasswordExpires'].$gt).toBeInstanceOf(Date);
    expect(update.$inc).toEqual({ tokenVersion: 1 });
  });
});

describe('verify account', () => {
  it('rejects operator objects', async () => {
    const res = await post('/api/users/verify-account', {
      id: { $exists: true }, token: { $ne: 'x' }
    });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).not.toHaveBeenCalled();
  });

  it('accepts string inputs', async () => {
    findOneAndUpdate.mockImplementation(() => Promise.resolve({ _id: 'x' }));
    const res = await post('/api/users/verify-account', {
      id: '5deaeae628e84b2bac6a5000', token: 'abc'
    });
    expect(res.status).toBe(200);
    expect(findOneAndUpdate.mock.calls[0][0]['emailTokens.verify']).toBe('abc');
  });
});

describe('reverify account', () => {
  it('rejects non string e-mail', async () => {
    const res = await post('/api/users/reverify-account', { email: ['a@b.com', 'c@d.com'] });
    expect(res.status).toBe(500);
    expect(findOneAndUpdate).not.toHaveBeenCalled();
  });
});
