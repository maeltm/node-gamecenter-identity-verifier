# node-gamecenter-identity-verifier
[![Build Status][travisimg]][travis]
[![Coverage Status][coverallsimg]][coveralls]

This is library to validate a apple's gamecenter identity of localplayer for consuming it in [node.js][node] backend server.

## Installation

```bash
npm install gamecenter-identity-verifier --save
```

## Usage

```js
var verifier = require('gamecenter-identity-verifier');

// identity from client.
// Reference:  https://developer.apple.com/library/ios/documentation/GameKit/Reference/GKLocalPlayer_Ref/index.html#//apple_ref/occ/instm/GKLocalPlayer/generateIdentityVerificationSignatureWithCompletionHandler

var identity = {
  publicKeyUrl: 'https://valid.apple.com/public/timeout.cer',
  timestamp: 1460981421303,
  signature: 'PoDwf39DCN464B49jJCU0d9Y0J',
  salt: 'saltST==',
  playerId: 'G:1111111',
  bundleId: 'com.valid.app'
};

verifier.verify(identity, function (err, token) {
  if (!err) {
    // use token in here.
    console.log(token);
  }
});
```

## Tests

```bash
npm test
```
or
```bash
npm prepare
```

## Contributing

In lieu of a formal styleguide, take care to maintain the existing coding style.
Add unit tests for any new or changed functionality. Lint and test your code.

## Third-party libraries

The following third-party libraries are used by this module:

* request: https://github.com/request/request - to get google's oauth2 federated signon certs.
* underscore: http://underscorejs.org

## Inspired by

* apple's api document - https://developer.apple.com/library/ios/documentation/GameKit/Reference/GKLocalPlayer_Ref/index.html#//apple_ref/occ/instm/GKLocalPlayer/generateIdentityVerificationSignatureWithCompletionHandler
* stackoverflow - http://stackoverflow.com/questions/17408729/how-to-authenticate-the-gklocalplayer-on-my-third-party-server

## Release History

* 0.1.1 Fix bug in convert method for timestamp to UInt64BE
* 0.1.0 Initial release

[travisimg]: https://travis-ci.org/maeltm/node-gamecenter-identity-verifier.svg?branch=master
[travis]: https://travis-ci.org/maeltm/node-gamecenter-identity-verifier
[coverallsimg]: https://coveralls.io/repos/maeltm/node-gamecenter-identity-verifier/badge.svg?branch=master&service=github
[coveralls]: https://coveralls.io/github/maeltm/node-gamecenter-identity-verifier?branch=master
[node]: http://nodejs.org/
