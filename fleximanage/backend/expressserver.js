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

const { version } = require('./package.json');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const configs = require('./configs')();
const swaggerUI = require('swagger-ui-express');
const yamljs = require('yamljs');
const express = require('express');
const cors = require('./routes/cors');
const cookieParser = require('cookie-parser');
const OpenApiValidator = require('express-openapi-validator');
const openapiRouter = require('./utils/openapiRouter');
const createError = require('http-errors');
const passport = require('passport');
const auth = require('./authenticate');
const { connectRouter } = require('./routes/connect');
const morgan = require('morgan');
const logger = require('./logging/logging')({ module: module.filename, type: 'req' });
const { reqLogger, errLogger } = require('./logging/request-logging');
const serialize = require('serialize-javascript');
const { mongoSanitizer } = require('./utils/security');

// periodic tasks
const deviceStatus = require('./periodic/deviceStatus')();
const deviceQueues = require('./periodic/deviceQueue')();
const deviceSwVersion = require('./periodic/deviceSwVersion')();
const deviceSwUpgrade = require('./periodic/deviceperiodicUpgrade')();
const notifyUsers = require('./periodic/notifyUsers')();
const releasePendingTunnels = require('./periodic/releasePendingTunnels')();
const appRules = require('./periodic/appRules')();
const applications = require('./periodic/applications')();
const statusesInDb = require('./periodic/statusesInDb')();

require('./applicationLogic/initializeApps');

// rate limiter
const rateLimit = require('express-rate-limit');
const RateLimitStore = require('./rateLimitStore');

// Internal routers definition
const adminRouter = require('./routes/admin');
const ticketsRouter = require('./routes/tickets')(
  configs.get('ticketingSystemUsername', 'string'),
  configs.get('ticketingSystemToken', 'string'),
  configs.get('ticketingSystemUrl', 'string'),
  configs.get('ticketingSystemAccountId', 'string')
);

// WSS
const WebSocket = require('ws');
const connections = require('./websocket/Connections')();
const broker = require('./broker/broker.js');

class ExpressServer {
  constructor (port, securePort, openApiYaml) {
    this.port = port;
    this.securePort = securePort;
    this.app = express();
    this.openApiPath = openApiYaml;
    this.schema = yamljs.load(openApiYaml);
    const restServerUrl = configs.get('restServerUrl', 'list');
    const servers = this.schema.servers.filter(server => server.url.includes(restServerUrl));
    if (servers.length === 0) {
      this.schema.servers.unshift(...restServerUrl.map((restServer, idx) => {
        return {
          description: `Local Server #${idx + 1}`,
          url: restServer + '/api'
        };
      }));
    };

    this.setupMiddleware = this.setupMiddleware.bind(this);
    this.addErrorHandler = this.addErrorHandler.bind(this);
    this.onError = this.onError.bind(this);
    this.onListening = this.onListening.bind(this);
    this.launch = this.launch.bind(this);
    this.close = this.close.bind(this);

    this.setupMiddleware();
  }

  async setupMiddleware () {
    // Needed to get the public IP if behind a proxy. Trust only the configured
    // number of hops / addresses, otherwise X-Forwarded-For can be spoofed by clients
    this.app.set('trust proxy', ExpressServer.getTrustProxySetting());

    // Don't expose system internals in response headers
    this.app.disable('x-powered-by');

    // Basic security headers
    this.app.use(ExpressServer.securityHeaders);

    // Start periodic device tasks
    deviceStatus.start();
    deviceQueues.start();
    deviceSwVersion.start();
    deviceSwUpgrade.start();
    notifyUsers.start();
    appRules.start();
    applications.start();
    statusesInDb.start();
    releasePendingTunnels.start();

    // Secure traffic only
    this.app.all('*', (req, res, next) => {
      // Allow Let's encrypt certbot to access its certificate dirctory
      if (!configs.get('shouldRedirectHttps', 'boolean') ||
          req.secure || req.url.startsWith('/.well-known/acme-challenge')) {
        return next();
      } else {
        return res.redirect(
          307, 'https://' + req.hostname + ':' + configs.get('redirectHttpsPort') + req.url
        );
      }
    });

    // CORS headers for all requests
    this.app.use(cors.cors);

    // Static files and the client index, served before the request logger
    // and the rate limiter. Routes allowed without authentication
    this.app.get('/', (req, res, next) => this.sendIndexFile(req, res).catch(next));
    this.app.use(express.static(path.join(__dirname, configs.get('clientStaticDir'))));

    // Request logging middleware - must be defined before routers.
    this.app.use(reqLogger);

    // Use morgan request logger in development mode
    if (configs.get('environment') === 'development') this.app.use(morgan('dev'));

    // Global rate limiter to protect against DoS attacks
    // Windows size of 5 minutes
    const inMemoryStore = new RateLimitStore(5 * 60 * 1000);
    const rateLimiter = rateLimit({
      store: inMemoryStore,
      // Rate limit for requests in 5 min per IP address
      max: configs.get('userIpReqRateLimit', 'number'),
      message: { error: 'Request rate limit exceeded' },
      onLimitReached: (req, res, options) => {
        logger.error(
          'Request rate limit exceeded. blocking request', {
            params: { ip: req.ip },
            req: req
          });
      }
    });
    this.app.use(rateLimiter);

    // General settings here
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: false }));
    this.app.use(cookieParser());

    // Reject requests containing MongoDB operators (keys starting with '$')
    // in body, query or params, before any router is called
    this.app.use(mongoSanitizer);

    // no authentication
    this.app.use('/api/connect', connectRouter);
    this.app.use('/api/users', require('./routes/users'));

    // add API documentation
    this.app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(this.schema));

    // initialize passport and authentication
    this.app.use(passport.initialize());

    // Enable db admin only in development mode, when explicitly enabled and
    // basic authentication credentials are configured
    if (configs.get('environment') === 'development' &&
      configs.get('enableDbAdmin', 'boolean') === true) {
      const mongoExpressConfig = require('./mongo_express_config');
      const { username, password } = mongoExpressConfig.basicAuth ?? {};
      if (!mongoExpressConfig.useBasicAuth || !username || !password || password === 'pass') {
        logger.error('UI database access is not enabled, set ME_CONFIG_BASICAUTH_USERNAME ' +
          'and ME_CONFIG_BASICAUTH_PASSWORD to enable it');
      } else {
        logger.warn('Warning: Enabling UI database access');
        // mongo database UI
        const mongoExpress = require('mongo-express/lib/middleware');
        const expressApp = await mongoExpress(mongoExpressConfig);
        this.app.use('/admindb', expressApp);
      }
    }

    // Enable routes for non-authorized links
    this.app.use('/ok', express.static(path.join(__dirname, 'public', 'ok.html')));
    this.app.use('/spec', express.static(path.join(__dirname, 'api', 'openapi.yaml')));
    this.app.get('/hello', (req, res) => res.send('Hello World'));

    this.app.get('/api/version', (req, res) => res.json({ version }));
    this.app.get('/api/restServers', (req, res) => res.json({ version }));

    this.app.use(cors.corsWithOptions);
    this.app.use(auth.verifyUserJWT);

    // Intialize routes
    this.app.use('/api/portals', require('./routes/portals'));
    this.app.use('/api/admin', adminRouter);
    this.app.use('/api/tickets', ticketsRouter);

    this.app.use(
      OpenApiValidator.middleware({
        apiSpec: this.openApiPath,
        validateRequests: configs.get('validateOpenAPIRequest', 'boolean'),
        validateResponses: configs.get('validateOpenAPIResponse', 'boolean')
      })
    );

    this.app.use(openapiRouter(this.schema.components.schemas));

    await this.launch();
  }

  /**
   * Get the client index.html file, cached until the file is modified
   * @return {Promise<string>} index.html content
   */
  async getIndexFile () {
    const indexPath = path.join(__dirname, configs.get('clientStaticDir'), 'index.html');
    const { mtimeMs } = await fs.promises.stat(indexPath);
    if (!this.indexCache || this.indexCache.mtimeMs !== mtimeMs) {
      const content = (await fs.promises.readFile(indexPath)).toString();
      // transformed index per client configuration
      this.indexCache = { mtimeMs, content, transformed: new Map() };
    }
    return this.indexCache;
  }

  async sendIndexFile (req, res) {
    // get client config based on request object
    const clientConfig = configs.getClientConfig(req);

    const transformIndex = (origIndex) => {
      let modifiedIndex = configs.get('removeBranding', 'boolean')
        ? origIndex.replace('<title>flexiWAN Management</title>',
          `<title>${configs.get('companyName')} Management</title>`)
        : origIndex;
      const m = modifiedIndex.match(/const __FLEXIWAN_SERVER_CONFIG__=(.*?);/);
      if (m instanceof Array && m.length > 0) { // successful match
        // Update default config with backend variables.
        // The default config is merged in the browser, to avoid evaluating it on the server
        modifiedIndex = modifiedIndex.replace(m[0],
          'const __FLEXIWAN_SERVER_CONFIG__=Object.assign(' + m[1] + ',' +
          serialize(clientConfig, { isJSON: true }) + ');');
      }
      return modifiedIndex;
    };

    // The client configuration depends only on the configured servers used by the request,
    // so the number of cached versions is bounded
    const { content, transformed } = await this.getIndexFile();
    const cacheKey = JSON.stringify(clientConfig);
    let transformedIndex = transformed.get(cacheKey);
    if (transformedIndex === undefined) {
      transformedIndex = transformIndex(content);
      if (transformed.size < 100) transformed.set(cacheKey, transformedIndex);
    }
    res.send(transformedIndex);
  }

  addErrorHandler () {
    // "catchall" handler, for any request that doesn't match one above, send back index.html file.
    this.app.get('*', (req, res, next) => {
      logger.info('Route not found', { req: req });
      this.sendIndexFile(req, res).catch(next);
    });

    // catch 404 and forward to error handler
    this.app.use(function (req, res, next) {
      next(createError(404));
    });

    // Request error logger - must be defined after all routers
    // Set log severity on the request to log errors only for 5xx status codes.
    this.app.use((err, req, res, next) => {
      req.logSeverity = err.status || 500;
      next(err);
    });
    this.app.use(errLogger);

    /**
     * suppressed eslint rule: The next variable is required here, even though it's not used.
     *
     ** */
    // eslint-disable-next-line no-unused-vars
    this.app.use((error, req, res, next) => {
      const status = error.status || error.statusCode || 500;
      // Don't expose internal error details for unexpected server errors
      const errorResponse = (status >= 500 && !error.expose && !error.status)
        ? 'Internal server error'
        : error.error || error.message || error.errors || 'Unknown error';
      res.status(status);
      res.type('json');
      res.json({ error: errorResponse });
    });
  }

  /**
   * Event listener for HTTP/HTTPS server "error" event.
   */
  onError (port) {
    return function (error) {
      if (error.syscall !== 'listen') {
        throw error;
      }

      const bind = 'Port ' + port;

      // handle specific listen errors with friendly messages
      /* eslint-disable no-unreachable */
      switch (error.code) {
        case 'EACCES':
          console.error(bind + ' requires elevated privileges');
          process.exit(1);
          break;
        case 'EADDRINUSE':
          console.error(bind + ' is already in use');
          process.exit(1);
          break;
        default:
          throw error;
      }
    };
  }

  /**
  * Event listener for HTTP server "listening" event.
  */
  onListening (server) {
    return function () {
      const addr = server.address();
      const bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
      console.debug('Listening on ' + bind);
    };
  }

  async launch () {
    this.addErrorHandler();

    try {
      this.server = http.createServer(this.app);

      this.options = ExpressServer.getHttpsOptions();
      this.secureServer = https.createServer(this.options, this.app);

      // setup wss here
      this.wss = new WebSocket.Server({
        server: configs.get('shouldRedirectHttps', 'boolean') ? this.secureServer : this.server,
        verifyClient: connections.verifyDevice,
        // Limit the size of messages received from devices
        maxPayload: configs.get('deviceWsMaxPayload', 'number')
      });

      connections.registerConnectCallback('broker', broker.deviceConnectionOpened);
      connections.registerCloseCallback('broker', broker.deviceConnectionClosed);
      connections.registerCloseCallback('deviceStatus', deviceStatus.deviceConnectionClosed);

      this.wss.on('connection', connections.createConnection);
      console.log('Websocket server running');

      this.server.listen(this.port, () => {
        console.log('HTTP server listening on port', { params: { port: this.port } });
      });
      this.server.on('error', this.onError(this.port));
      this.server.on('listening', this.onListening(this.server));

      this.secureServer.listen(this.securePort, () => {
        console.log('HTTPS server listening on port', { params: { port: this.securePort } });
      });
      this.secureServer.on('error', this.onError(this.securePort));
      this.secureServer.on('listening', this.onListening(this.secureServer));
    } catch (error) {
      console.error('Express server launch error', { params: { message: error.message } });
      logger.error('Express server launch error', { params: { message: error.message } });
      // Can't serve requests, exit so the error is visible and the process can be restarted
      process.exit(1);
    }
  }

  /**
   * Get the express 'trust proxy' setting from the configuration
   * @return {number|boolean|string} trust proxy setting
   */
  static getTrustProxySetting () {
    const value = configs.get('trustProxy');
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    const str = String(value ?? '').trim();
    if (/^\d+$/.test(str)) return +str;
    if (str.toLowerCase() === 'true') {
      logger.warn('trustProxy is set to true, client IP addresses can be spoofed');
      return true;
    }
    if (str === '' || str.toLowerCase() === 'false') return false;
    // list of trusted addresses / subnets
    return str;
  }

  /**
   * Middleware that adds basic security headers to every response
   */
  static securityHeaders (req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (req.secure) {
      res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    }
    return next();
  }

  /**
   * Load the HTTPS key and certificate. In development environment, when the files
   * don't exist, a temporary self signed certificate is generated.
   * @return {Object} https options with key and cert
   */
  static getHttpsOptions () {
    const keyFile = path.join(__dirname, 'bin', configs.get('httpsCertKey'));
    const certFile = path.join(__dirname, 'bin', configs.get('httpsCert'));
    if (fs.existsSync(keyFile) && fs.existsSync(certFile)) {
      return { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
    }
    if (!['development', 'testing'].includes(configs.get('environment'))) {
      throw new Error(`HTTPS key or certificate file not found (${keyFile}, ${certFile}). ` +
        'Configure httpsCertKey and httpsCert (HTTPS_CERT_KEY, HTTPS_CERT env variables)');
    }
    logger.warn('HTTPS key or certificate not found, generating a temporary self signed ' +
      'certificate for development', { params: { keyFile, certFile } });
    console.warn('HTTPS key or certificate not found, using a temporary self signed certificate');
    return ExpressServer.generateSelfSignedCert();
  }

  /**
   * Generate a self signed certificate for development
   * @return {Object} key and cert in PEM format
   */
  static generateSelfSignedCert () {
    const forge = require('node-forge');
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01' + forge.util.bytesToHex(forge.random.getBytesSync(8));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    const hosts = configs.get('restServerUrl', 'list').map(u => {
      try { return new URL(u).hostname; } catch (err) { return null; }
    }).filter(h => h);
    const attrs = [{ name: 'commonName', value: hosts[0] || 'localhost' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([{
      name: 'subjectAltName',
      altNames: [...new Set([...hosts, 'localhost'])].map(h => ({ type: 2, value: h }))
    }]);
    cert.sign(keys.privateKey, forge.md.sha256.create());
    return {
      key: forge.pki.privateKeyToPem(keys.privateKey),
      cert: forge.pki.certificateToPem(cert)
    };
  }

  async close () {
    if (this.server !== undefined) {
      await this.server.close();
      console.log(`HTTP Server on port ${this.port} shut down`);
    }
    if (this.secureServer !== undefined) {
      await this.secureServer.close();
      console.log(`HTTPS Server on port ${this.securePort} shut down`);
    }
  }
}

module.exports = ExpressServer;
