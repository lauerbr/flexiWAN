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

const logger = require('../logging/logging')({ module: module.filename, type: 'periodic' });
const configs = require('../configs')();
const fetchUtils = require('../utils/fetchUtils');
const applicationStore = require('../models/applicationStore');

/***
 * This class serves as the applications update manager, responsible for
 * polling the repository for applications file and replacement of the
 * file in the database when remote update time has changed.
 ***/
class ApplicationsUpdateManager {
  /**
    * Creates a ApplicationsUpdateManager instance
    */
  constructor () {
    this.applicationsUri = configs.get('applicationsUrl');
  }

  /**
    * A static singleton that creates an ApplicationsUpdateManager Instance.
    *
    * @static
    * @return an instance of an ApplicationsUpdateManager class
    */
  static getApplicationsManagerInstance () {
    if (applicationsUpdater) return applicationsUpdater;
    applicationsUpdater = new ApplicationsUpdateManager();
    return applicationsUpdater;
  }

  /**
    * Polls the applications file
    * @async
    * @return {void}
    */
  async pollApplications () {
    logger.info('Begin fetching appStore file', {
      params: { applicationsUri: this.applicationsUri }
    });
    try {
      const body = await fetchUtils.fetchWithRetry(this.applicationsUri, 3);
      logger.debug('Imported applications response received', {
        params: { time: body.meta.time, rulesCount: body.applications.length }
      });

      const appList = body.applications || [];

      const options = {
        upsert: true,
        useFindAndModify: false,
        new: true,
        runValidators: true
      };

      let isUpdated = false;

      for (let i = 0; i < appList.length; i++) {
        // skip if app is not changed on repository
        let app = await applicationStore.findOne({ identifier: appList[i].identifier });
        if (app && app.repositoryTime === body.meta.time) {
          continue;
        }

        isUpdated = true;

        const set = { $set: { repositoryTime: body.meta.time, ...appList[i] } };
        app = await applicationStore.findOneAndUpdate(
          { identifier: appList[i].identifier },
          set,
          options
        );
      }

      if (isUpdated) {
        logger.info('appStore database updated', {
          params: { time: body.meta.time, appsCount: appList.length }
        });
      }
    } catch (err) {
      logger.error('Failed to query applications file', {
        params: { err: err.message }
      });
    }
  }
}

let applicationsUpdater = null;
module.exports = {
  getApplicationsManagerInstance: ApplicationsUpdateManager.getApplicationsManagerInstance
};
