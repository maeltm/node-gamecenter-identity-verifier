'use strict';

var crypto = require('crypto');
var https = require('https');
var url = require('url');

var cache = {}; // (publicKey -> cert) cache

function verifyPublicKeyUrl(publicKeyUrl) {
  var parsedUrl = url.parse(publicKeyUrl);
  if (parsedUrl.protocol !== 'https:') {
    return false;
  }

  var hostnameParts = parsedUrl.hostname.split('.');
  var length = hostnameParts.length;
  var domainParts = hostnameParts.slice(length-2, length);
  var domain = domainParts.join('.');
  if (domain !== 'apple.com') {
    return false;
  }

  return true;
}

function convertX509CertToPEM(X509Cert) {
  var pemPreFix = '-----BEGIN CERTIFICATE-----\n';
  var pemPostFix = '-----END CERTIFICATE-----';

  var base64 = X509Cert;
  var certBody = base64.match(new RegExp('.{0,64}', 'g')).join('\n');

  return pemPreFix + certBody + pemPostFix;
}

function getAppleCertificate(publicKeyUrl, callback) {
  if (!verifyPublicKeyUrl(publicKeyUrl)) {
    callback(new Error('Invalid publicKeyUrl'), null);
    return;
  }

  if (cache[publicKeyUrl]) {
    return callback(null, cache[publicKeyUrl]);
  }

  https.get(publicKeyUrl, function (res) {
    var data = '';
    res.on('data', function(chunk) {
      data += chunk.toString('base64');
    });
    res.on('end', function() {
      var cert = convertX509CertToPEM(data);

      if (res.headers['cache-control']) { // if there's a cache-control header
        var expire = res.headers['cache-control'].match(/max-age=([0-9]+)/);
        if (expire) { // if we got max-age
          cache[publicKeyUrl] = cert; // save in cache
          // we'll expire the cache entry later, as per max-age
          setTimeout(function () {
            delete cache[publicKeyUrl];
          }, parseInt(expire[1], 10) * 1000);
        }
      }
      callback(null, cert);
    });
  }).on('error', function(e) {
    callback(e);
  });
}

/* jslint bitwise:true */
function convertTimestampToBigEndian(timestamp) {
  // The timestamp parameter in Big-Endian UInt-64 format
  var buffer = new Buffer.alloc(8);
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

  if (!verifier.verify(publicKey, idToken.signature, 'base64')) {
    throw new Error('Invalid Signature');
  }
}

exports.verify = function (idToken, callback) {
  getAppleCertificate(idToken.publicKeyUrl, function (err, publicKey) {
    if (!err) {
      try {
        verifySignature(publicKey, idToken);
        callback(null, idToken);
      } catch (e) {
        callback(e, null);
      }
    } else {
      callback(err, null);
    }
  });
};
