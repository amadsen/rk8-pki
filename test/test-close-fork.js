var rk8pki = require('../rk8-pki.js')({
    pregenerateKeyPairs: 0
});

(function (assert, done) {
    var expectedPublic = '-----BEGIN PUBLIC KEY-',
        expectedPrivate = '-----BEGIN RSA PRIVATE KEY-';
    rk8pki.keypair( function (err, keypair) {
        if(err){
            assert.fail(err);
        }
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
        done();
    });
})(require('assert'), function () {
    var timer = setTimeout( function(){
        console.log(
            '\nHandles:\n',
            process._getActiveHandles(),
            '\nRequest:\n',
            process._getActiveRequests()
        );
        process._getActiveHandles().forEach( function(handle, idx) {
            if (process.stdin === handle) {
                console.log(idx, 'is stdin');
            } else if (process.stdin._handle === handle) {
                console.log(idx, 'is stdin._handle');
            } else if (process.stdout === handle) {
                console.log(idx, 'is stdout');
            } else if (process.stdout._handle === handle) {
                console.log(idx, 'is stdout._handle');
            } else if (process.stderr === handle) {
                console.log(idx, 'is stderr');
            } else if (process.stderr._handle === handle) {
                console.log(idx, 'is stderr._handle');
            }
        });
    }, 500);
    timer.unref();
    console.log('test done and timer unref()\'d');
});
