/*
global toString
 */
'use strict';

var assert = require('assert');
var verifier = require('../lib/main');

function isError(error) {
  return toString.call(error) === '[object Error]';
}

// a real token is used to check caching behavior, but sharing it should have no security consequences
var testToken = { 
  playerId: 'G:1965586982',
  publicKeyUrl: 'https://static.gc.apple.com/public-key/gc-prod-4.cer',
  timestamp: 1565257031287,
  signature: 'uqLBTr9Uex8zCpc1UQ1MIDMitb+HUat2Mah4Kw6AVLSGe0gGNJXlih2i5X+0ZwVY0S9zY2NHWi2gFjmhjt\/4kxWGMkupqXX5H\/qhE2m7hzox6lZJpH98ZEUbouWRfZX2ZhUlCkAX09oRNi7fI7mWL1\/o88MaI\/y6k6tLr14JTzmlxgdyhw+QRLxRPA6NuvUlRSJpyJ4aGtNH5\/wHdKQWL8nUnFYiYmaY8R7IjzNxPfy8UJTUWmeZvMSgND4u8EjADPsz7ZtZyWAPi8kYcAb6M8k0jwLD3vrYCB8XXyO2RQb/FY2TM4zJuI7PzLlvvgOJXbbfVtHx7Evnm5NYoyzgzw==',
  salt: 'DzqqrQ==',
  bundleId: 'cloud.xtralife.gamecenterauth'
};

describe.only('caching test', function () {
  it('should be slow for first check',
    function (done) {
      verifier.verify(testToken, function (error) {
        assert.equal(isError(error), false);
        done();
      });
    });

  it('should take less than 2ms for next checks',
    function (done) {
      this.timeout(2);
      verifier.verify(testToken, function (error) {
        assert.equal(isError(error), false);
        done();
      });
    });
});

