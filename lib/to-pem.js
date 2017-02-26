"use strict";

var LRU = require("lru-cache");

module.exports = function(settings) {
    var forge = settings.forge,
        pki = forge.pki;

    var cacheSettings = (settings.cache || {});

    var memoizedKeyMaps = {
      public: LRU( cacheSettings.public || 50 ),
      private: LRU( cacheSettings.private || 50 )
    };

    function publicKeyToPem (pubKey) {
      // generate the pem encoded public key for future lookup for transfer and storage
      var pubPem = pki.publicKeyToPem(pubKey);

      // store a mapping from the pem encoded key to the forge public key
      memoizedKeyMaps.public.set(pubPem, pubKey);
      return pubPem;
    }

    function privateKeyToPem (privKey) {
      // generate the pem encoded private key for future lookup for transfer and storage
      var privPem = pki.privateKeyToPem(privKey);

      // store a mapping from the pem encoded key to the forge public key
      memoizedKeyMaps.private.set(privPem, privKey);
      return privPem;
    }

    function publicKeyFromPem (pubPem) {
      // only recalculate the forge public key if we have to
      var pubKey = memoizedKeyMaps.public.get(pubPem) || pki.publicKeyFromPem(pubPem);

      // store a mapping from the pem encoded key to the forge public key
      memoizedKeyMaps.public.set(pubKey, pubPem);
      return pubKey;
    }

    function privateKeyFromPem (privPem) {
      // only recalculate the forge private key if we have to
      var privKey = memoizedKeyMaps.private.get(privPem) || pki.privateKeyFromPem(privPem);

      // store a mapping from the pem encoded key to the forge public key
      memoizedKeyMaps.private.set(privPem, privKey);
      return privKey;
    }

    return {
      publicKeyToPem: publicKeyToPem,
      publicKeyFromPem: publicKeyFromPem,
      privateKeyToPem: privateKeyToPem,
      privateKeyFromPem: privateKeyFromPem
    }
};
