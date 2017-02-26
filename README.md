# Rk8 PKI

This module wraps up [forge.js](https://github.com/digitalbazaar/forge)' RSA KEM logic for easy use. The interface it exposes is, at the highest level, generic enough that the underlying implementation could be changed in the future. However, doing so would mean changing the available configuration settings (and a major version bump).

## Installation

~~~bash
npm install --save rk8-pki
~~~

## Use 

This module exports an initialization function to which settings are passed. This function returns an object with 3 methods - [keypair](#keypair), [encrypt](#encrypt), and [decrypt](#decrypt).

Example:

~~~javascript
var initRk8pki = require('../rk8-pki.js');
var rk8pki = initRk8pki({
    pregenerateKeyPairs: 0
});
var assert = require('assert');

var original = 'Original value';

rk8pki.keypair( function (err, keypair) {
    if(err){
        assert.fail(err);
    }
	rk8pki.encrypt(
		original, 
		keypair.publicKey, 
		function (err, encrypted) {
			if(err){
				return assert.fail(err);
			}
			
			rk8pki.decrypt(
				encrypted,
				keypair.privateKey,
				function (err, decrypted) {
					if(err){
						return assert.fail(err);
					}
					
					assert.equal(decrypted.toString(), original, 'Encrypted object decrypts to the same string as the original');
				}
			);
		}
	);
});
~~~

### Configuration 

#### initRk8pki(settings)
The initialization function is passed a configuration object with these keys:

##### useNativeCode

Tells us whether we should allow `forge.js` to use native modules, which can significantly improve performance but may cause portablity issues.
 
Default: `false`

##### cache

An object with two keys - `public` and `private` - that determine how many PEM-encoded public or private keys can have their decoded representations cached in an LRU cache so they don't have to be decoded again.

Default: ```{
	public: 50,
	private: 50
}```

##### pregenerateKeyPairs

A number indicating how many keypairs should be generated in the background and cached so that `keypair` doesn't have to wait for them to be generated and PEM-encoded, which can be a lengthy process.

Default: `10`

##### fork

Generating keypairs, PEM-encoding keys, and decoding PEM-encoded keys can be lengthy processes that block the event loop. By default `rk8-pki` mitigates this by forking a single child process to handle the actual work. If **fork** is set to `false` the work is done on the current process instead.

### API

#### <a name="keypair"></a>keypair([timeout], callback)

This function generates a 2048 bit PEM-encoded RSA key pair with a public key and a private key.

**timeout** is the number of milliseconds to wait for the operation to complete.

**callback** is a `function(err, result)` to be called when the operation completes or returns an error.

To be documented.

#### <a name="encrypt"></a>encrypt(message, pemEncodedPublicKey, [timeout], callback)

...uses SHA 256 and AES-GCM and returns an object containing `k`, `iv`, `m`, and `t` properties, where

+ `k` - is the RSA-KEM encapsulated secret key
+ `iv` - is the initialization vector
+ `m` - is the cipher text (encrypted message)
+ `t` - is the cipher mode tag

To be documented.

#### <a name="decrypt"></a>decrypt(encrypted, pemEncodedPrivateKey, [timeout], callback)

**encrypted** is expected to be an object containing `k`, `iv`, `m`, and `t` properties, where

+ `k` - is the RSA-KEM encapsulated secret key
+ `iv` - is the initialization vector
+ `m` - is the cipher text (encrypted message)
+ `t` - is the cipher mode tag

that was created using SHA 256 and AES-GCM.

**pemEncodedPrivateKey** is a PEM-encode RSA private key

**timeout** is the number of milliseconds to wait for the operation to complete.

**callback** is a `function(err, result)` to be called when the operation completes or returns an error.

To be documented.