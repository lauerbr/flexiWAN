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

const logger = require('../logging/logging')({ module: module.filename, type: 'periodic' });
/***
 * This class runs periodic tasks for the site, such as collecting devices status
 *
 ***/
class Periodic {
  constructor () {
    // Holds the periodic tasks. Each task referred by the name key (must be unique)
    // and contains function, handle and period (in msec)
    this.tasks = {};

    // this binding
    this.registerTask = this.registerTask.bind(this);
    this.startTask = this.startTask.bind(this);
    this.endTask = this.endTask.bind(this);
  }

  // Register task to periodic tasks
  registerTask (name, func, period) {
    this.tasks[name] = { name: name, func: func, handle: null, period: period };
    logger.info('Registering periodic task', {
      params: { name: name },
      periodic: { task: this.tasks[name] }
    });
  }

  // Start a task
  startTask (name) {
    if (this.tasks[name]) {
      if (this.tasks[name].handle == null) {
        logger.info('Starting periodic task', {
          params: { name: name },
          periodic: { task: this.tasks[name] }
        });

        const timer = setInterval(this.tasks[name].func, this.tasks[name].period);
        this.tasks[name].handle = timer;
      } else {
        logger.info('Trying to start an already running task',
          { params: { name: name }, periodic: { task: this.tasks[name] } });
      }
    } else {
      logger.warn('Task is not registered',
        { params: { name: name }, periodic: { task: this.tasks[name] } });
    }
  }

  endTask (name) {
    if (this.tasks[name]) {
      if (this.tasks[name].handle != null) {
        logger.info('Ending periodic task',
          { params: { name: name }, periodic: { task: this.tasks[name] } });
        clearInterval(this.tasks[name].handle);
        this.tasks[name].handle = null;
      } else {
        logger.info('Trying to end an already ended task',
          { params: { name: name }, periodic: { task: this.tasks[name] } });
      }
    } else {
      logger.warn('Task is not registered',
        { params: { name: name }, periodic: { task: this.tasks[name] } });
    }
  }
}

var periodic = null;
module.exports = function () {
  if (periodic) return periodic;
  else {
    periodic = new Periodic();
    return periodic;
  };
};
