/*
global toString
 */
'use strict';

var assert = require('assert');
var crypto = require('crypto');
var fs = require('fs');
var verifier = require('../lib/main');
var nock = require('nock');

function calculateSignature(payload) {
  var privateKey = fs.readFileSync('./test/fixtures/private.pem', 'utf-8');
  var signer = crypto.createSign('sha256');
  signer.update(payload.playerId, 'utf8');
  signer.update(payload.bundleId, 'utf8');
  signer.update(verifier.convertTimestampToBigEndian(payload.timestamp));
  signer.update(payload.salt, 'base64');

  var signature = signer.sign(privateKey, 'base64');
  return signature;
}

describe('verifying gameCenter identity', function () {

  beforeEach(function () {

    nock('https://valid.apple.com')
      .get('/public/public.cer')
      .replyWithFile(200, __dirname + '/fixtures/public.der');
  });

  // TODO timeouts are out of scope for now
  // xit('should fail to verify apple game center identity if request is failed(timeout)',
  //   function (done) {
  //   var testToken = {
  //     publicKeyUrl: 'https://valid.apple.com/public/timeout.cer',
  //     timestamp: 1460981421303,
  //     salt: 'saltST==',
  //     playerId: 'G:1111111',
  //     bundleId: 'com.valid.app'
  //   };
  //   testToken.signature = calculateSignature(testToken);
  //
  //   verifier.verify(testToken, function (error, token) {
  //     assert(error instanceof verifier.SignatureValidationError);
  //     assert.equal(error.message, 'timeout');
  //     assert.equal(token, null);
  //     done();
  //   });
  // });

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
      assert.equal(error, null);
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
      assert.equal(error, null);
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
      assert(error instanceof verifier.SignatureValidationError);
      assert.equal(error.message, 'Invalid publicKeyUrl: should use https');
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
      assert(error instanceof verifier.SignatureValidationError);
      assert.equal(error.message, 'Invalid publicKeyUrl: host should be apple.com');
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
      assert(error instanceof verifier.SignatureValidationError);
      assert.equal(error.message, 'Invalid Signature');
      assert.equal(token, null);
      done();
    });
  });
});
