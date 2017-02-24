"use strict";

var fork = require('child_process').fork,
    forge = require('node-forge')({disableNativeCode: true}),
    pki = forge.pki;

var toPem = require('./lib/to-pem.js')({
    forge: forge
});

var generateKeyPair = require('./lib/generate-keypair.js')({
    forge: forge,
    toPem: toPem
});

function encrypt ( msg, pemPublicKey, done ) {
    setImmediate( function() {
        // convert a PEM-formatted public key to a Forge public key
        var publicKey = toPem.publicKeyFromPem(pemPublicKey);

        // Use RSA-KEM to encrypt the msg with a randomly
        // generated one time password and AES-256
        var kdf1 = new forge.kem.kdf1(forge.md.sha256.create()),
            kem = forge.kem.rsa.create(kdf1),
            otp = kem.encrypt(publicKey, 32),
            iv = forge.random.getBytesSync(12),
            cipher = forge.cipher.createCipher('AES-GCM', otp.key),
            aesCipherText,
            encryptedOTP;

        cipher.start({iv: iv});
        cipher.update( forge.util.createBuffer(msg) );
        cipher.finish();
        aesCipherText = cipher.output;

        return done( null, {
          k: otp.encapsulation,
          iv: iv,
          m: aesCipherText,
          t: cipher.mode.tag
        });
    });
}

function decrypt ( cipherObj, pemPrivateKey, done ) {
    setImmediate( function() {
        // convert a PEM-formatted private key to a Forge private key
        var privateKey = toPem.privateKeyFromPem(pemPrivateKey);

        var kdf1 = new forge.kem.kdf1(forge.md.sha256.create()),
            kem = forge.kem.rsa.create(kdf1),
            key = kem.decrypt(privateKey, cipherObj.k, 32),
            decipher,
            success;

        decipher = forge.cipher.createDecipher('AES-GCM', key);
        decipher.start({
          iv: cipherObj.iv,
          tag: cipherObj.t
        });
        decipher.update(forge.util.createBuffer(cipherObj.m));
        success = decipher.finish();
        if(success){
          return done( null, decipher.output.getBytes() );
        }
        return done( new Error('Unable to decrypt cipher with provided key.') );
    });
}

var actions = {
  keypair: generateKeyPair,
  encrypt: encrypt,
  decrypt: decrypt,
  unsupported: function(){ return undefined; }
};

if(module === process.mainModule){
    // listen on the process for events that should trigger
    process.on('message', function(msg) {
        var fn = actions[ msg.action ] || actions.unsupported;

        fn.apply(null, [].concat(msg.args, function(err, result){
            var response = {
                id: msg.id,
            }

            if (err) {
                response.error = err;
            } else {
                response.result = result;
            }
            process.send(response);
        }));
    });
} else {
    module.exports = (function(){
        var child = fork(__filename);
        var actorCallbacks = {};

        child.on('message', function(response){
            var cb = actorCallbacks[ response.id ];
            if('function' !== typeof cb) {
                return;
            }
            return cb(response.error, response.result);
        });

        return Object.keys(actions).reduce( function (exported, action) {
            exported[action] = function () {
                var msg = {};

                // gather the args
                msg.args = [].slice.call(arguments, 0, -1);

                if('function' !== typeof arguments[ msg.args.length ]) {
                    // you don't want a result; we won't do anything
                    return;
                }

                // assign the action
                msg.action = action;

                // generate the callback id
                msg.id = [action].concat(process.hrtime(), Math.ceil(Math.random()*100000) ).join('|');

                // save the callback on our queue
                actorCallbacks[msg.id] = arguments[ msg.args.length ];

                // send a message to our child process
                child.send(msg);
            };
            return exported;
        }, {});
    })();
}
