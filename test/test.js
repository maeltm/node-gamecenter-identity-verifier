'use strict';

// var _ = require('underscore');
// var assert = require('assert');
// var verifier = require('../lib/main');

describe('verifying gameCenter identity', function () {
  it('should succeed to verify apple game center identity');
  it('should fail to get publicKey with http: protocol');
  it('should fail to get publicKey if domain is not apple.com');
  it('should fail to verify signature if signature is invalid');
});
