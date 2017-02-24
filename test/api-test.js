var test = require('tape');

var rk8pki = require('../rk8-pki.js');

test('keypair() should return an object with a PEM-encoded public key', function (assert) {
    var expected = '-----BEGIN PUBLIC KEY-';
    rk8pki.keypair( function (err, keypair) {
        assert.equal(keypair.publicKey.substring(0, expected.length), expected );
        assert.end();
    });
});

test('keypair() should return an object with a PEM-encoded private key', function (assert) {
    var expected = '-----BEGIN RSA PRIVATE KEY-';
    rk8pki.keypair( function (err, keypair) {
        assert.equal( keypair.privateKey.substring(0, expected.length), expected );
        assert.end();
    });
});

test('encrypt() should return an object with k, iv, m, and t', function (assert) {
    var original = 'Original message';
    rk8pki.keypair( function (err, keypair) {
        rk8pki.encrypt(original, keypair.publicKey, function (err, encrypted) {
            if(err){
                return assert.end(err);
            }
            assert.equal( Object.keys(encrypted), ['k', 'iv', 'm', 't'] );
            rk8pki.decrypt(encrypted, keypair.privateKey, function (err, decrypted) {
                if(err){
                    return assert.end(err);
                }
                assert.equal(decrypted.toString(), original);
                assert.end();
            });
        });
    });
});
