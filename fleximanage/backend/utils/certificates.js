// flexiWAN SD-WAN software - flexiEdge, flexiManage.
// For more information go to https://flexiwan.com
// Copyright (C) 2022  flexiWAN Ltd.

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

const EasyRSA = require('easyrsa').default;
const forge = require('node-forge');
const fs = require('fs');
const { randomBytes, generateKeyPair } = require('crypto');
const { promisify } = require('util');
const generateKeyPairAsync = promisify(generateKeyPair);
const logger = require('../logging/logging')({ module: module.filename, type: 'req' });

const deleteFolderRecursive = path => {
  if (!fs.existsSync(path)) {
    return;
  }

  fs.readdirSync(path).forEach((file, index) => {
    const curPath = path + '/' + file;
    if (fs.lstatSync(curPath).isDirectory()) { // recurse
      deleteFolderRecursive(curPath);
    } else { // delete file
      fs.unlinkSync(curPath);
    }
  });
  fs.rmdirSync(path);
};

/**
 * Generate an RSA private key with the native (non blocking) node crypto,
 * easyrsa generates the keys in pure javascript on the main thread
 * @param  {number} bits key size
 * @return {Promise<string>} private key in PKCS#1 PEM format
 */
const generateRsaPrivateKey = async (bits = 2048) => {
  const { privateKey } = await generateKeyPairAsync('rsa', {
    modulusLength: bits,
    publicExponent: 0x10001,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  });
  return privateKey;
};

const generateRemoteVpnPKI = async (orgName) => {
  const res = {
    caCert: null,
    caKey: null,
    serverCert: null,
    serverKey: null,
    clientCert: null,
    clientKey: null
  };

  let caPrivateKey, serverPrivateKey, clientPrivateKey;
  try {
    [caPrivateKey, serverPrivateKey, clientPrivateKey] = await Promise.all([
      generateRsaPrivateKey(), generateRsaPrivateKey(), generateRsaPrivateKey()
    ]);
  } catch (err) {
    logger.error('failed to create keys', { params: { orgName, err: err.message } });
    throw new Error('An error occurred while creating the keys for your organization');
  }

  return new Promise((resolve, reject) => {
    const pkiDir = `tmp/openvpn_pki/${orgName}`;

    // Make sure pki tmp folder is not exists, otherwise the package will throw an error
    deleteFolderRecursive(pkiDir);

    const easyrsa = new EasyRSA({ pkiDir: pkiDir });
    easyrsa.initPKI()
      .then(t => {
        return easyrsa.buildCA({ privateKey: caPrivateKey });
      })
      .then(data => {
        res.caCert = forge.pki.certificateToPem(data.cert);
        res.caKey = forge.pki.privateKeyToPem(data.privateKey);

        const commonName = 'server';
        return easyrsa.createServer({ commonName, nopass: true, privateKey: serverPrivateKey });
      }).then((data) => {
        res.serverCert = forge.pki.certificateToPem(data.cert);
        res.serverKey = forge.pki.privateKeyToPem(data.privateKey);

        const commonName = 'client';
        return easyrsa.createClient({ commonName, nopass: true, privateKey: clientPrivateKey });
      })
      .then((data) => {
        res.clientCert = forge.pki.certificateToPem(data.cert);
        res.clientKey = forge.pki.privateKeyToPem(data.privateKey);
        return resolve(res);
      })
      .catch(err => {
        logger.error('failed to create certificates', { params: { orgName, err } });
        const errMsg =
          new Error('An error occurred while creating the keys for your organization');
        return reject(errMsg);
      })
      .finally(() => {
        // on any case, remove the pki dir
        deleteFolderRecursive(pkiDir);
      });
  });
};

const generateTlsKey = () => {
  const buf = randomBytes(256);
  const hex = buf.toString('hex');

  const key = splitLineEveryNChars(hex, /(.{32})/g);

  const ret =
`-----BEGIN OpenVPN Static key V1-----
${key}
-----END OpenVPN Static key V1-----`;

  return ret;
};

const splitLineEveryNChars = (str, regex) => {
  const tmp = str.replace(regex, '$1<break>');
  const arr = tmp.split('<break>');

  // Remove the last <break>
  arr.pop();

  const finalString = arr.join('\n');

  return finalString;
};

module.exports = {
  generateRemoteVpnPKI,
  generateTlsKey
};
