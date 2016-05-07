'use strict';

var _ = require('underscore');
var assert = require('assert');
var crypto = require('crypto');
var fs = require('fs');
var request = require('request');
var sinon = require('sinon');
var verifier = require('../lib/main');

/* jslint bitwise:true */
function convertTimestampToBigEndian(timestamp) {
  // The timestamp parameter in Big-Endian UInt-64 format
  var buffer = new Buffer(8);
  buffer.fill(0);

  var high = ~~(timestamp / 0xffffffff); // jshint ignore:line
  var low = timestamp % (0xffffffff + 0x1); // jshint ignore:line

  buffer.writeUInt32BE(parseInt(high, 10), 0);
  buffer.writeUInt32BE(parseInt(low, 10), 4);

  return buffer;
}
/* jslint bitwise:false */

function calculateSignature(payload) {
  var privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');
  var signer = crypto.createSign('sha256');
  signer.update(payload.playerId, 'utf8');
  signer.update(payload.bundleId, 'utf8');
  signer.update(convertTimestampToBigEndian(payload.timestamp));
  signer.update(payload.salt, 'base64');

  var signature = signer.sign(privateKey, 'base64');
  return signature;
}

describe('verifying gameCenter identity', function () {
  before(function (done) {
    var testPublicKey = fs.readFileSync('./test/fixtures/public.der');
    sinon
      .stub(request, 'get', function (options, callback) {
        if (options.uri.indexOf('timeout') !== -1) {
          callback(new Error('timeout'), { statusCode: 404, headers: {} }, null);
        } else {
          callback(null, { statusCode: 200, headers: {} }, testPublicKey);
        }
      });
    done();
  });

  after(function (done) {
    request.get.restore();
    done();
  });

  it('should fail to verify apple game center identity if request is failed(timeout)',
  function (done) {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/timeout.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    verifier.verify(testToken, function (error, token) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'timeout');
      assert.equal(token, null);
      done();
    });
  });

  it('should succeed to verify apple game center identity',
  function (done) {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    verifier.verify(testToken, function (error, token) {
      assert.equal(_.isError(error), false);
      assert.equal(token.playerId, testToken.playerId);
      done();
    });
  });

  /*jshint multistr: true */
  it('should succeed to verify identity when most significant (left-most) bit of \
timestamp high and low bit block is 1',
  function (done) {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/public.cer',
      timestamp: 1462525134342,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    verifier.verify(testToken, function (error, token) {
      assert.equal(_.isError(error), false);
      assert.equal(token.playerId, testToken.playerId);
      done();
    });
  });

  it('should fail to get publicKey with http: protocol',
  function (done) {
    var testToken = {
      publicKeyUrl: 'http://valid.apple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    verifier.verify(testToken, function (error, token) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid publicKeyUrl');
      assert.equal(token, null);
      done();
    });
  });

  it('should fail to get publicKey if domain is not apple.com',
  function (done) {
    var testToken = {
      publicKeyUrl: 'https://invalid.badapple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);

    verifier.verify(testToken, function (error, token) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid publicKeyUrl');
      assert.equal(token, null);
      done();
    });
  });

  it('should fail to verify signature if signature is invalid',
  function (done) {
    var testToken = {
      publicKeyUrl: 'https://valid.apple.com/public/public.cer',
      timestamp: 1460981421303,
      salt: 'saltST==',
      playerId: 'G:1111111',
      bundleId: 'com.valid.app'
    };
    testToken.signature = calculateSignature(testToken);
    testToken.salt = 'NOsalt==';

    verifier.verify(testToken, function (error, token) {
      assert.equal(_.isError(error), true);
      assert.equal(error.message, 'Invalid Signature');
      assert.equal(token, null);
      done();
    });
  });
});
