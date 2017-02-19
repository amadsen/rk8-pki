"use strict";

module.exports = function(settings) {
    var forge = settings.forge,
        pki = forge.pki,
        toPem = forge.toPem;

    var pregeneratedKeyPairs = [],
        desiredCacheLength = settings.cacheLength >= 0 ? settings.cacheLength : 10,
        pending = false;

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
    if (desiredCacheLength > 0) {
        cacheNewKeyPairs();        
    }

    function generateKeyPair (done) {
      return pki.rsa.generateKeyPair({bits: 2048, workers: -1}, function(err, keypair){
        if (err) {
          return done(err);
        }
        return done(null, {
          // convert a Forge public key to PEM-format
          publicKey: toPem.publicKeyToPem(keypair.publicKey),
          // convert a Forge private key to PEM-format
          privateKey: toPem.privateKeyToPem(keypair.privateKey)
        })
      });
    }

    return function getKeyPair(done){
      var keypair = pregeneratedKeyPairs.shift(),
        fn = (!keypair)? generateKeyPair : function (cb) {
          // replenish the cache
          setImmediate(cacheNewKeyPairs);
          cb(null, keypair);
        };

      return fn(done);
    }
};
