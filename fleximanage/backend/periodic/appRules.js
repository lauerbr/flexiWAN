// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2020  flexiWAN Ltd.

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
const AppRulesUpdater = require('../deviceLogic/AppRulesUpdateManager');
const ha = require('../utils/highAvailability')(configs.get('redisUrl'));

/***
 * This class periodically checks if the latest AppIdentification rules were changed
 * and if so, updates the database with the new version
 ***/
class AppRules {
  /**
    * Creates an instance of the AppRules class
    */
  constructor () {
    this.appRulesUpdater = null;
    this.start = this.start.bind(this);
    this.periodicCheckAppRules = this.periodicCheckAppRules.bind(this);

    this.taskInfo = {
      name: 'check_app_rules',
      func: this.periodicCheckAppRules,
      handle: null,
      period: (1000 * 60 * 60 * 24) // Runs once in a day
    };
  }

  /**
    * Starts the check_app_rules periodic task.
    * @return {void}
    */
  start () {
    this.appRulesUpdater = AppRulesUpdater.getAppRulesUpdaterInstance();

    // Get the app rules upon starting up
    this.periodicCheckAppRules();

    const { name, func, period } = this.taskInfo;
    periodic.registerTask(name, func, period);
    periodic.startTask(name);
  }

  /**
    * Polls app rules repository to check if
    * a rules file has been released.
    * @return {void}
    */
  periodicCheckAppRules () {
    ha.runIfActive(() => {
      this.appRulesUpdater.pollAppRules();
    });
  }
}

let appRules = null;
module.exports = function () {
  if (appRules) return appRules;
  appRules = new AppRules();
  return appRules;
};
