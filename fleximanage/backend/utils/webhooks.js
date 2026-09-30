/**
 * This module sends info to web hooks
 */
const fetch = require('fetch-with-proxy').default;
const dns = require('dns');
const net = require('net');
const https = require('https');
const http = require('http');
const path = require('path');
// Use the same proxy detection as fetch-with-proxy
const { getProxyForUrl } = require(require.resolve('proxy-from-env', {
  paths: [path.dirname(require.resolve('fetch-with-proxy'))]
}));
const { isPrivateAddress } = require('./security');
const logger = require('../logging/logging')({
  module: module.filename,
  type: 'req'
});

// Timeout for sending a webhook, in msec
const WEBHOOK_TIMEOUT = 10000;
// Maximum webhook response size in bytes
const WEBHOOK_MAX_RESPONSE_SIZE = 1024 * 1024;

/**
 * DNS lookup that fails for non public addresses, used to prevent
 * requests to internal addresses also when DNS changes after the check
 */
const publicOnlyLookup = (hostname, options, callback) => {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const addresses = Array.isArray(address) ? address.map(a => a.address) : [address];
    if (addresses.some(a => isPrivateAddress(a))) {
      return callback(new Error(`Webhook address ${hostname} is not allowed`));
    }
    return callback(null, address, family);
  });
};

/**
 * Check that a webhook URL doesn't point to a private, loopback, link-local
 * or other internal address
 * @param  {string} url webhook URL
 * @return {Promise<boolean>} true if the URL is allowed
 */
const isPublicWebhookUrl = async (url) => {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (err) {
    return false;
  }
  if (!['https:', 'http:'].includes(parsed.protocol)) return false;
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname)) return !isPrivateAddress(hostname);
  try {
    const addresses = await dns.promises.lookup(hostname, { all: true });
    return addresses.length > 0 && addresses.every(a => !isPrivateAddress(a.address));
  } catch (err) {
    return false;
  }
};

class WebHooks {
  constructor () {
    this.sendToWebHook = this.sendToWebHook.bind(this);
  }

  /**
     * Sends a POST request to web hooks.
     * @async
     * @param  {string}         url     url to send the message to
     * @param  {Object}         message JSON object to send in body
     * @param  {string}         secret  secret key to send in the message (secret field)
     * @param  {string}         msgTitle A string describing the type of the message,
     * such as notification, user invitation, etc.
     * @param  {Object}         options
     * @param  {boolean}        options.blockPrivateAddresses don't send to internal addresses,
     * must be set for URLs provided by users
     * @return {boolean|Object}         false if send failed, response object otherwise
     */
  async sendToWebHook (url, message, secret = null, msgTitle = null, options = {}) {
    // For an empty url (development), return true
    if (url === '') return Promise.resolve(true);
    if (typeof url !== 'string') return false;
    const { blockPrivateAddresses = false } = options;
    const fetchOptions = {};
    if (blockPrivateAddresses) {
      if (!await isPublicWebhookUrl(url)) {
        logger.warn('Webhook URL is not allowed', { params: { url } });
        return false;
      }
      // When not using a proxy, verify the address again when connecting
      if (!getProxyForUrl(url)) {
        fetchOptions.agent = url.startsWith('https:')
          ? new https.Agent({ lookup: publicOnlyLookup })
          : new http.Agent({ lookup: publicOnlyLookup });
      }
    }
    let messageObject;

    // Check if the URL belongs to Slack or MS Teams
    if (url.includes('hooks.slack.com')) {
      // Format the message for Slack
      let formattedMsgForSlack = Object.keys(message).map(
        key => `${key}: ${message[key]}`).join('\n');
      if (msgTitle) {
        formattedMsgForSlack = `*${msgTitle}*\n` + formattedMsgForSlack;
      }
      messageObject = { text: formattedMsgForSlack };
    // TODO identify MS teams in a more specific way since this check is not specific enough
    } else if (url.includes('.office.com')) {
      // Format the message for MS teams
      let formattedMsgForTeams = Object.keys(message).map(
        key => `${key}: ${message[key]}`).join('<br>');
      if (msgTitle) {
        formattedMsgForTeams = `**${msgTitle}**<br>${formattedMsgForTeams}`;
      }
      messageObject = {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        summary: msgTitle || 'FlexiWAN message',
        sections: [{ text: formattedMsgForTeams }]
      };
    } else {
      if (msgTitle) {
        message = { subject: msgTitle, ...message };
      }
      messageObject = message;
    }

    messageObject = { ...messageObject, ...(secret && { secret: secret }) };
    const data = JSON.stringify(messageObject);

    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': data.length,
      'User-Agent': 'flexiWAN webhook plugin'
    };

    return fetch(url, {
      method: 'POST',
      headers: headers,
      body: data,
      // Don't follow redirects, they may point to internal addresses
      redirect: 'manual',
      timeout: WEBHOOK_TIMEOUT,
      size: WEBHOOK_MAX_RESPONSE_SIZE,
      ...fetchOptions
    })
      .then(response => {
        return response.json()
          .then(json => {
            response.message = json;
            return response;
          },
          error => {
            throw error;
          });
      },
      error => {
        throw error;
      })
      .then(response => {
        if (response.ok) {
          // Success handling
          if (response.message === 1 || response.message.status === 'success') return true;
          return false;
        } else return false;
      })
      .catch((error) => {
        logger.error('Failed to send webhook', { params: { url, error: error?.message } });
        // General error handling
        return false;
      });
  }
}

let webHooksHandler = null;
module.exports = function (secretKey) {
  if (webHooksHandler) return webHooksHandler;
  else {
    webHooksHandler = new WebHooks();
    return webHooksHandler;
  }
};
