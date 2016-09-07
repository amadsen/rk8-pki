"use strict";

var forge = require('node-forge')({disableNativeCode: true}),
    pki = forge.pki;

var memoizedKeyMaps = {
  public: {},
  private: {}
};

var pregeneratedKeyPairs = [],
  desiredCacheLength = 2,
  pending = false;

// TODO: move the transformation of pki keys to and from PEM format off of the
// main process.

function publicKeyToPem (pubKey) {
  // generate the pem encoded public key for future lookup for transfer and storage
  var pubPem = pki.publicKeyToPem(pubKey);

  // store a mapping from the pem encoded key to the forge public key
  // TODO: add TTL to this
  memoizedKeyMaps.public[pubPem] = pubKey;
  return pubPem;
}

function privateKeyToPem (privKey) {
  // generate the pem encoded private key for future lookup for transfer and storage
  var privPem = pki.privateKeyToPem(privKey);

  // store a mapping from the pem encoded key to the forge public key
  // TODO: add TTL to this
  memoizedKeyMaps.private[privPem] = privKey;
  return privPem;
}

function publicKeyFromPem (pubPem) {
  // only recalculate the forge public key if we have to
  var pubKey = memoizedKeyMaps.public[pubPem] || pki.publicKeyFromPem(pubPem);

  // store a mapping from the pem encoded key to the forge public key
  // TODO: add TTL to this
  memoizedKeyMaps.public[pubKey] = pubPem;
  return pubKey;
}

function privateKeyFromPem (privPem) {
  // only recalculate the forge private key if we have to
  var privKey = memoizedKeyMaps.private[privPem] || pki.privateKeyFromPem(privPem);

  // store a mapping from the pem encoded key to the forge public key
  // TODO: add TTL to this
  memoizedKeyMaps.private[privPem] = privKey;
  return privKey;
}

/*
generate a list of keypairs, stored in memory, ahead of time to speed up
registration process.
*/
function cacheNewKeyPairs () {
  console.log('Number of cached pairs: ', pregeneratedKeyPairs.length);
  console.log('Number of pending pair generations: ', pending);

  if(pregeneratedKeyPairs.length < desiredCacheLength && !pending) {
    pending = true;
    generateKeyPair(function (err, pemKeyPair) {
      pending = false;
      pregeneratedKeyPairs.push(pemKeyPair);
      cacheNewKeyPairs();
    });
  }
}

// start caching
cacheNewKeyPairs();

function generateKeyPair (done) {
  return pki.rsa.generateKeyPair({bits: 2048, workers: -1}, function(err, keypair){
    if (err) {
      return done(err);
    }
    return done(null, {
      // convert a Forge public key to PEM-format
      publicKey: publicKeyToPem(keypair.publicKey),
      // convert a Forge private key to PEM-format
      privateKey: privateKeyToPem(keypair.privateKey)
    })
  });
}

module.exports = {
  keypair: function(done){
    var keypair = pregeneratedKeyPairs.shift(),
      fn = (!keypair)? generateKeyPair : function (cb) {
        // replenish the cache
        setImmediate(cacheNewKeyPairs);
        cb(null, keypair);
      };

    return fn(done);
  },
  encrypt: function ( msg, pemPublicKey ) {
    // convert a PEM-formatted public key to a Forge public key
    var publicKey = publicKeyFromPem(pemPublicKey);

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
  decrypt: function ( cipherObj, pemPrivateKey ) {
    // convert a PEM-formatted private key to a Forge private key
    var privateKey = privateKeyFromPem(pemPrivateKey);

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
      return decipher.output.getBytes();
    }
    //return undefined;
  }
};
