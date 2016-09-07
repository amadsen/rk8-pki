"use strict";
var memoizedKeyMaps = {
  public: {},
  private: {}
};

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

module.exports = {
  publicKeyToPem: publicKeyToPem,
  publicKeyFromPem: publicKeyFromPem,
  privateKeyToPem: privateKeyToPem,
  privateKeyFromPem: privateKeyFromPem
}
