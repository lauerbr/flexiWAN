// Get config, uses development as default config
// It's assumed that the mongoUrl field is set by environment variable for
// non development environments
const configs = require('./configs')('development');

module.exports = {
  dbConnectionUri: configs.get('mongoUrl')
};
