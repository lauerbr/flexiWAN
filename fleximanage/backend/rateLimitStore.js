// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2019  flexiWAN Ltd.

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

class MemoryStore {
  constructor (windowMs) {
    this.windowMs = windowMs;
    this.hits = {};
    this.resetTime = this.calculateNextResetTime();
    this.periodicResetInterval();
  }

  incr (key, cb) {
    if (this.hits[key]) {
      this.hits[key]++;
    } else {
      this.hits[key] = 1;
    }

    cb(null, this.hits[key], this.resetTime);
  }

  decrement (key) {
    if (this.hits[key]) {
      this.hits[key]--;
    }
  }

  // export an API to allow hits all IPs to be reset
  resetAll () {
    this.hits = {};
    this.resetTime = this.calculateNextResetTime();
  }

  // export an API to allow hits from one IP to be reset
  resetKey (key) {
    delete this.hits[key];
  }

  // export an API to allow retrieving hits of a specific key
  getHitsByKey (key) {
    return this.hits[key];
  }

  periodicResetInterval () {
    const interval = setInterval(this.resetAll.bind(this), this.windowMs);
    if (interval.unref) {
      interval.unref();
    }
  }

  calculateNextResetTime () {
    const d = new Date();
    d.setMilliseconds(d.getMilliseconds() + this.windowMs);
    return d;
  }
}

module.exports = MemoryStore;
