'use strict';

var crypto = require('crypto');
var https = require('https');

var cache = {}; // (publicKey -> cert) cache

class SignatureValidationError extends Error {}

function convertX509CertToPEM(X509Cert) {
  var pemPreFix = '-----BEGIN CERTIFICATE-----\n';
  var pemPostFix = '-----END CERTIFICATE-----';

  var base64 = X509Cert;
  var certBody = base64.match(new RegExp('.{0,64}', 'g')).join('\n');

  return pemPreFix + certBody + pemPostFix;
}

async function getAppleCertificate(publicKeyUrl, useCaching) {
  const url = new URL(publicKeyUrl)
  if (!url.host.endsWith('.apple.com')) {
    throw new SignatureValidationError('Invalid publicKeyUrl: host should be apple.com');
  }
  if (url.protocol !== 'https:') {
    throw new SignatureValidationError('Invalid publicKeyUrl: should use https');
  }

  if (cache[publicKeyUrl]) {
    return cache[publicKeyUrl];
  }

  const [error, base64Data, res] = await new Promise(resolve => {
      let data = '';
      https.get(publicKeyUrl, res => {
        res
          .on('error', error => resolve([error]))
          .on('data', chunk => data += chunk.toString('base64'))
          .on('end', () => resolve([null, data, res]))
        })
    })

  if (error) {
    console.error('http error! ' + error)
    throw new SignatureValidationError(error)
  }

  const publicKey = convertX509CertToPEM(base64Data);

  if (useCaching && res.headers['cache-control']) { // if there's a cache-control header
    const expire = res.headers['cache-control'].match(/max-age=([0-9]+)/);
    const parsed = parseInt(expire[1], 10) * 1000
    // check parsed for falsy value, eg. null or zero
    if (parsed) { // if we got max-age
      cache[publicKeyUrl] = publicKey; // save in cache
      // we'll expire the cache entry later, as per max-age
      setTimeout(function () {
          delete cache[publicKeyUrl];
        }, parsed)
        .unref();
    }
  }

  return publicKey
}

/* jslint bitwise:true */
function convertTimestampToBigEndian(timestamp) {
  // The timestamp parameter in Big-Endian UInt-64 format
  var buffer = Buffer.alloc(8);
  buffer.fill(0);

  var high = ~~(timestamp / 0xffffffff); // jshint ignore:line
  var low = timestamp % (0xffffffff + 0x1); // jshint ignore:line

  buffer.writeUInt32BE(parseInt(high, 10), 0);
  buffer.writeUInt32BE(parseInt(low, 10), 4);

  return buffer;
}
/* jslint bitwise:false */

function verifySignature(publicKey, idToken) {
  var verifier = crypto.createVerify('sha256');
  verifier.update(idToken.playerId, 'utf8');
  verifier.update(idToken.bundleId, 'utf8');
  verifier.update(convertTimestampToBigEndian(idToken.timestamp));
  verifier.update(idToken.salt, 'base64');

  const valid = verifier.verify(publicKey, idToken.signature, 'base64')
  return valid
}

async function verify (idToken, useCache = true) {
  const publicKey = await getAppleCertificate(idToken.publicKeyUrl, useCache);
  return verifySignature(publicKey, idToken);
};

module.exports = {
  verify: function (idToken, cb) {
    if (!cb)
      return verify(idToken)

    verify(idToken)
      .then(isValid => {
        if (!isValid)
          return cb(new SignatureValidationError("Invalid Signature"), null)

        cb(null, idToken)
      })
      .catch(err => cb(err, null))
  },
  SignatureValidationError,
  convertTimestampToBigEndian,
}
