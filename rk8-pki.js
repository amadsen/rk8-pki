"use strict";

var forge = require('node-forge');

module.export = {
  keypair: function(done){
    return forge.pki.rsa.generateKeyPair({bits: 2048, workers: -1}, done);
  },
  encrypt: function ( msg, publicKey ) {
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

    return {
      k: otp.encapsulation,
      iv: iv,
      m: aesCipherText,
      t: cipher.mode.tag
    };
  },
  decrypt: function ( cipherObj, privateKey ) {
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
    decipher.update(cipherObj.m);
    success = decipher.finish();
    if(success){
      return decipher.output.getBytes();
    }
    //return undefined;
  }
};
