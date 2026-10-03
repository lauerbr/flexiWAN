// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2021  flexiWAN Ltd.

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

/**
 * This module is a modified version of redis-leader
 */
'use strict';

const crypto = require('crypto');
const util = require('util');
const uuid = require('uuid');
const EventEmitter = require('events').EventEmitter;

// Extend the lock TTL only if this instance still holds it (atomic check-and-set)
const RENEW_SCRIPT = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0`;

// Release the lock only if this instance holds it (atomic check-and-delete)
const RELEASE_SCRIPT = `
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0`;

// Make the key less prone to collision
const hashKey = function (key) {
  return 'leader:' + crypto.createHash('sha1').update(key).digest('hex');
};

function Leader (redis, options) {
  options = options || {};
  this.id = uuid.v4();
  this.redis = redis;
  this.options = {};
  this.options.ttl = options.ttl || 10000; // Lock time to live in milliseconds
  this.options.wait = options.wait || 1000; // time between 2 tries to get lock
  // time between 2 renewals of the lock, a third of the TTL so the lock survives
  // a missed renewal or a short event loop stall
  this.options.renew = options.renew || Math.floor(this.options.ttl / 3);

  this.key = hashKey(options.key || 'default');
}

util.inherits(Leader, EventEmitter);

/**
  * Renew leader as elected
  */
Leader.prototype._renew = function _renew () {
  // extend the lock only if we are still the leader, in one atomic operation
  this.redis.eval(RENEW_SCRIPT, 1, this.key, this.id, this.options.ttl, function (err, res) {
    if (err) {
      // keep trying on the next interval, the lock is lost only when the TTL expires
      this.emit('error', err);
      return;
    }
    if (!res) {
      clearInterval(this.renewId);
      clearTimeout(this.electId);
      this.electId = setTimeout(Leader.prototype.elect.bind(this), this.options.wait);
      this.emit('revoked');
    }
  }.bind(this));
};

/**
  * Try to get elected as leader
  */
Leader.prototype.elect = function elect () {
  // atomic redis set
  this.redis.set(this.key, this.id, 'PX', this.options.ttl, 'NX', function (err, res) {
    if (err) {
      this.emit('error', err);
      clearTimeout(this.electId);
      clearInterval(this.renewId);
      this.electId = setTimeout(Leader.prototype.elect.bind(this), this.options.wait);
      return;
    }
    if (res !== null) {
      this.emit('elected');
      clearTimeout(this.electId);
      clearInterval(this.renewId);
      this.renewId = setInterval(Leader.prototype._renew.bind(this), this.options.renew);
    } else {
      // use setTimeout to avoid max call stack error
      clearTimeout(this.electId);
      clearInterval(this.renewId);
      this.electId = setTimeout(Leader.prototype.elect.bind(this), this.options.wait);
    }
  }.bind(this));
};

Leader.prototype.isLeader = function isLeader (done) {
  this.redis.get(this.key, function (err, id) {
    if (err) {
      return done(err);
    }
    done(null, (id === this.id));
  }.bind(this));
};

/**
  * if leader, stop being a leader
  * stop trying to be a leader
  */
Leader.prototype.stop = function stop () {
  clearInterval(this.renewId);
  clearTimeout(this.electId);
  // delete the lock only if we are the leader, in one atomic operation
  this.redis.eval(RELEASE_SCRIPT, 1, this.key, this.id, function (err, res) {
    if (err) {
      return this.emit('error', err);
    }
    if (res) this.emit('revoked');
  }.bind(this));
};

module.exports = Leader;
