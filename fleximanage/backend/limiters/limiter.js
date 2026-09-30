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

const { RateLimiterMemory, RateLimiterRedis } = require('rate-limiter-flexible');
const { createClient } = require('redis');
const configs = require('../configs')();
const { getRedisAuthUrl } = require('../utils/httpUtils');
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });

// Redis client shared by all limiters, created on first use
let redisClient = null;
const getRedisClient = () => {
  if (redisClient) return redisClient;
  const { redisAuth, redisUrlNoAuth } = getRedisAuthUrl(configs.get('redisUrl'));
  // with offline queue disabled, commands fail immediately when redis is not
  // connected and the in-memory insurance limiter is used
  redisClient = createClient({ url: redisUrlNoAuth, enable_offline_queue: false });
  if (redisAuth) redisClient.auth(redisAuth);
  redisClient.on('error', (err) => {
    logger.warn('Limiters redis client error', { params: { err: err.message } });
  });
  return redisClient;
};

class FwLimiter {
  constructor (name, counts, duration, blockDuration) {
    this.name = name;
    this.maxCount = counts;
    this.duration = duration;
    this.blockDuration = blockDuration;

    const limiterOpts = {
      points: counts,
      duration: duration,
      blockDuration: blockDuration
    };
    if (configs.get('limitersUseRedis', 'boolean')) {
      // Keep the limiter state in redis so it is shared by all flexiManage instances,
      // fall back to an in-memory limiter while redis is not available
      this.limiter = new RateLimiterRedis({
        ...limiterOpts,
        storeClient: getRedisClient(),
        keyPrefix: 'fw-limiter:' + name,
        insuranceLimiter: new RateLimiterMemory(limiterOpts)
      });
    } else {
      this.limiter = new RateLimiterMemory(limiterOpts);
    }
  }

  async use (key) {
    const response = { allowed: true, blockedNow: false, releasedNow: false };
    try {
      // try to consume a point. If blocked, an error will be thrown.
      const resConsume = await this.limiter.consume(key);
      // currently, it is not possible to pass a callback that is automatically
      // executed when the key expires.
      // So we call the release function on the next allowed time.
      if (resConsume.consumedPoints === 1) {
        logger.debug('Rate limiter consumed the first time for a key',
          { params: { limiterName: this.name, key, resConsume } }
        );
        response.releasedNow = true;
      }
    } catch (err) {
      // limiter is blocked.
      response.allowed = false;

      // check if blocked now or the key is already blocked
      if (err.consumedPoints === this.maxCount + 1) {
        logger.debug('Rate limiter blocked now for a key',
          { params: { key, err } }
        );
        response.blockedNow = true;
      }

      // check if during the blockage time, the same high rate is continues
      // in order to keep the same convention, we blocked only at the (points + 1).
      // For example, 5 times in 10 minutes. Only at the 6th, 11th, 16th times it will be blocked.
      // that's why we decrement one from the consumed points in the following check
      if ((err.consumedPoints - 1) % this.maxCount === 0) {
        logger.debug('Rate limiter blocked again the key due to continuous high rate',
          { params: { key, err } }
        );
        await this.limiter.block(key, this.blockDuration);
      }
    }

    return response;
  }

  async delete (key) {
    return this.limiter.delete(key);
  }

  async release (key) {
    const isBlocked = await this.isBlocked(key);
    if (!isBlocked) {
      return false;
    }

    const isDeleted = await this.delete(key);
    if (!isDeleted) {
      return false;
    }

    return true;
  }

  async isBlocked (key) {
    const res = await this.limiter.get(key);

    // remainingPoints is never negative in the redis store, use consumedPoints
    if (res !== null && res.consumedPoints > this.maxCount) {
      return true;
    }

    return false;
  }
};

module.exports = FwLimiter;
