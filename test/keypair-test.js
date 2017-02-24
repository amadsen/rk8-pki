var test = require('tape');

var forge = require('node-forge')({disableNativeCode: true}),
    toPem = require('../lib/to-pem.js')({
        forge: forge
    }),
    generateKeyPair = require('../lib/generate-keypair.js')({
        forge: forge,
        toPem: toPem,
        cacheLength: 0
    });

test('Should return an object with a PEM-encoded public key', function (assert) {
    var expected = '-----BEGIN PUBLIC KEY-';
    generateKeyPair( function (err, keypair) {
        assert.equal( keypair.publicKey.substring(0, expected.length), expected );
        assert.end();
    });
});

test('Should return an object with a PEM-encoded private key', function (assert) {
    var expected = '-----BEGIN RSA PRIVATE KEY-';
    generateKeyPair( function (err, keypair) {
        assert.equal( keypair.privateKey.substring(0, expected.length), expected );
        assert.end();
    });
});
