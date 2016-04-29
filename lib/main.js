'use strict';

var _             = require('underscore');
var crypto        = require('crypto');
var request       = require('request');
var url           = require('url');

var publicKey     = null;
var publicKeyURL  = null;

function verifyPublicKeyUrl(publicKeyUrl) {
  var parsedUrl = url.parse(publicKeyUrl);
  if (parsedUrl.protocol !== 'https:') {
    return false;
  }

  var hostnameParts = parsedUrl.hostname.split('.');
  var domainParts = _.rest(hostnameParts, hostnameParts.length - 2);
  var domain = domainParts.join('.');
  if (domain !== 'apple.com') {
    return false;
  }

  return true;
}

function convertX509CertToPEM(X509Cert) {
  var pemPreFix = '-----BEGIN CERTIFICATE-----\n';
  var pemPostFix = '-----END CERTIFICATE-----';

  var base64 = X509Cert.toString('base64');
  var certBody = base64.match(new RegExp('.{0,64}', 'g')).join('\n');

  return pemPreFix + certBody + pemPostFix;
}

function getAppleCertificate(publicKeyUrl, callback) {
  
  if (publicKey && publicKeyURL == publicKeyUrl) { return publicKey }
  
  if (!verifyPublicKeyUrl(publicKeyUrl)) {
    callback(new Error('Invalid publicKeyUrl'), null);
    return;
  }

  var options = {
    uri: publicKeyUrl,
    encoding: null
  };
  request.get(options, function (error, response, body) {
    if (!error && response.statusCode === 200) {
      var cert = convertX509CertToPEM(body);
      publicKey = cert
      callback(null, cert);
    } else {
      callback(error, null);
    }
  });
}

/* jslint bitwise:true */
function convertTimestampToBigEndian(timestamp) {
  // The timestamp parameter in Big-Endian UInt-64 format
  var buffer = new Buffer(8);
  buffer.fill(0);

  buffer.writeUInt32BE(parseInt(timestamp / 0xffffffff, 10), 0); // jshint ignore:line
  buffer.writeUInt32BE(parseInt(timestamp & 0xffffffff, 10), 4); // jshint ignore:line

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
