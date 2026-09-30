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

const configs = require('../configs')();
const periodic = require('./periodic')();
const DevSwUpdater = require('../deviceLogic/DevSwVersionUpdateManager');
const ha = require('../utils/highAvailability')(configs.get('redisUrl'));

/***
 * This class periodically checks if the latest device software has changed
 * and if so, updates the database with the new latest version
 ***/
class DeviceSwVersion {
  /**
     * Creates an instance of the DeviceSwVersion class
     */
  constructor () {
    this.devSwUpd = null;
    this.start = this.start.bind(this);
    this.periodicCheckSwVersion = this.periodicCheckSwVersion.bind(this);

    this.taskInfo = {
      name: 'check_device_sw_version',
      func: this.periodicCheckSwVersion,
      handle: null,
      period: 3600000 // Runs once an hour
    };
  }

  /**
    * Starts the check_device_sw_version periodic task.
    * @return {void}
    */
  start () {
    this.devSwUpd = DevSwUpdater.getSwVerUpdaterInstance();

    // Get the version upon starting up
    this.periodicCheckSwVersion();

    // Runs once every hour
    const { name, func, period } = this.taskInfo;
    periodic.registerTask(name, func, period);
    periodic.startTask(name);
  }

  /**
     * Polls device software repository to check if
     * a new software version has been released.
     * @return {void}
     */
  periodicCheckSwVersion () {
    ha.runIfActive(() => {
      this.devSwUpd.pollDevSwRepo();
    });
  }
}

let checkDevSw = null;
module.exports = function () {
  if (checkDevSw) return checkDevSw;
  checkDevSw = new DeviceSwVersion();
  return checkDevSw;
};
