var test = require('tape');

var forge = require('node-forge')({disableNativeCode: true}),
    toPem = require('../lib/to-pem.js')({
        forge: forge
    }),
    pki = forge.pki;

// test against another implementation
var ursa = require('ursa');



test('toPem.publicKeyToPem() converts forge public key to PEM encoded public key', function(assert) {
    var expected = '-----BEGIN PUBLIC KEY-';
    pki.rsa.generateKeyPair({bits: 2048, workers: -1}, function(err, keypair){
      if (err) {
        return assert.end(err);
      }

      var pubKey = toPem.publicKeyToPem(keypair.publicKey);
      assert.equal( typeof pubKey, 'string' );
      assert.equal( pubKey.substring(0, expected.length), expected );
      assert.end();
    });
});

test('toPem.publicKeyFromPem() converts PEM encoded public key to forge public key', function(assert) {
    var ursaKeys = ursa.generatePrivateKey(),
        ursaPubPem = ursaKeys.toPublicPem();

    var pubKey = toPem.publicKeyFromPem(ursaPubPem);
    assert.equal( typeof pubKey.verify, 'function' );
    assert.equal( typeof pubKey.encrypt, 'function' );
    assert.end();
});

test('toPem.privateKeyToPem() converts forge private key to PEM encoded private key', function(assert) {
    var expected = '-----BEGIN RSA PRIVATE KEY-';
    pki.rsa.generateKeyPair({bits: 2048, workers: -1}, function(err, keypair){
      if (err) {
        return assert.end(err);
      }

      var privKey = toPem.privateKeyToPem(keypair.privateKey);
      assert.equal( typeof privKey, 'string' );
      assert.equal( privKey.substring(0, expected.length), expected );
      assert.end();
    });
});

test('toPem.privateKeyFromPem() converts PEM encoded private key to forge private key', function(assert) {
    var ursaKeys = ursa.generatePrivateKey(),
        ursaPrivPem = ursaKeys.toPrivatePem();

    var privKey = toPem.privateKeyFromPem(ursaPrivPem);
    assert.equal( typeof privKey.sign, 'function' );
    assert.equal( typeof privKey.decrypt, 'function' );
    assert.end();
});
