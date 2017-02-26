var test = require('tape');

var rk8pki = require('../rk8-pki.js')({
    pregenerateKeyPairs: 0
});

test('keypair() should return an object with PEM-encoded public and private keys', function (assert) {
    var expectedPublic = '-----BEGIN PUBLIC KEY-',
        expectedPrivate = '-----BEGIN RSA PRIVATE KEY-';
    rk8pki.keypair( function (err, keypair) {
        assert.equal(
            keypair.publicKey.substring(0, expectedPublic.length),
            expectedPublic,
            'keypair.publicKey is a public key'
        );
        assert.equal(
            keypair.privateKey.substring(0, expectedPrivate.length),
            expectedPrivate,
            'keypair.privateKey is a private key'
        );
        assert.end();
    });
});

test('encrypt() should return an object with k, iv, m, and t which can be decrypt()ed with the private key', function (assert) {
    var original = 'Original message';
    rk8pki.keypair( function (err, keypair) {
        rk8pki.encrypt(original, keypair.publicKey, function (err, encrypted) {
            if(err){
                return assert.end(err);
            }
            assert.equal( Object.keys(encrypted).toString(), ['k', 'iv', 'm', 't'].toString(), 'Encrypted object has the proper keys.' );
            rk8pki.decrypt(encrypted, keypair.privateKey, function (err, decrypted) {
                if(err){
                    return assert.end(err);
                }
                assert.equal(decrypted.toString(), original, 'Encrypted object decrypts to the same string as the original');
                assert.end();
            });
        });
    });
});
