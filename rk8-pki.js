"use strict";

var fork = require('child_process').fork,
    initForge = require('node-forge'),
    initToPem = require('./lib/to-pem.js'),
    initGenerateKeyPair = require('./lib/generate-keypair.js');

var envPrefix = process.argv[3] || 'rk8-pki:' + Math.ceil(Math.random()*100000) + ':';

function unsupported () {
    return undefined;
}

function timeoutOrCallback(time, errorMsg, cb) {
    var t = setTimeout(function(){
        setImmediate(cb, new Error(errorMsg));
        cb = null;
    }, time);

    return function () {
        clearTimer(t);
        if ('function' === typeof cb) {
            return cb.apply(null, [].slice.call(arguments));
        }
    }
}

function setupChildProcess () {
    // pull our settings off of the child process environment
    var settings = Object.keys(process.env).reduce( function (settings, k) {
        if( envPrefix === k.substring(0, envPrefix.length) ) {
            settings[ k.substring(envPrefix.length) ] = JSON.parse( process.env[k] );
        }
        return settings;
    }, {});
    // use the setup function to initialize our actions in the same process
    settings.fork = false;
    var actions = setupRk8Pki( {}, settings );

    function handleActionMessage(msg) {
        var fn = actions[ msg.action ] || unsupported;

        fn.apply(null, [].concat(msg.args, function (err, result) {
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
    }

    process
        // listen for disconnect so we know the child should shut down
        .on('disconnect', function () {
            process.exit();
        })
        // listen on the process for events that should trigger actions
        .on('message', handleActionMessage);
}


/*
This function is exported when we are used as a module, but not
when we load ourself as a child process.
*/
function setupRk8Pki (target, settings) {
    var forge = initForge(settings.useNativeCode? {} : {disableNativeCode:true}),
        pki = forge.pki;

    var toPem = initToPem({
        cache: settings.cache,
        forge: forge
    });

    var generateKeyPair = initGenerateKeyPair({
        cacheLength: settings.pregenerateKeyPairs >=0 ? settings.pregenerateKeyPairs : 10,
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
      decrypt: decrypt
    };

    // the user does not want to use a background process,
    if (settings.fork === false) {
        // just export a direct interface.
        return Object.keys(actions).reduce( function (exported, action) {
            exported[ action ] = actions[ action ];
            return exported;
        }, target);
    }

    // We are going to uref() our child process, so we create an object to
    // track pending callbacks and use a Timer to keep the process running
    // until those callbacks are resolved.
    function checkPending () {
        if(Object.keys(pending).length === 0) {
            return keepAlive.unref();
        }
        return keepAlive.ref();
    }
    var pending = {},
        // the interval length is arbitrary and mostly irelevant, so long as
        // it is long enough not to trigger frequently. It really just gives
        // us a persistent Timer object we can use to keep the process running
        // by calling ref() whenever we need to.
        keepAlive = setInterval(checkPending, 1000);
    // start off with keepAlive timer unref()'ed
    checkPending();

    // prepare and unref() the child process that does the work as well
    // as the IPC channel we use to communicate with it.
    var child = fork(__filename, ['child', envPrefix], {
        env: Object.keys(settings).reduce( function(env, k) {
            env[ envPrefix+k ] = JSON.stringify( settings[k] );
            return env;
        }, {}),
        stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });
    // https://github.com/nodejs/node/issues/9313 means child.channel is coming
    // but child._channel already exists.
    (child.channel ? child.channel : child._channel).unref();
    child.unref();

    function childResponseListener (id, cb, response) {
        // if this isn't our message, set the listener again
        if (id != response.id) {
            // we use child.once with listeners bound to id's and callbacks
            // so that the process can exit if we don't have any
            // pending actions.
            console.log('Resetting listener for', id);
            return child.once('message', childResponseListener.bind(id, cb));
        }
        console.log('Resolving listener for', id);
        return cb(response.error, response.result);
    }

    return Object.keys(actions).reduce( function (exported, action) {
        exported[action] = function () {
            var fn = actions[ action ], // we won't call it, but we need it's length
                timeout = -1, // our default timeout is unlimited
                msg = {};

            // gather the args
            msg.args = [].slice.call(arguments, 0, -1);

            var cb = arguments[ msg.args.length ];
            if ('function' !== typeof cb) {
                // you don't want a result; we won't do anything
                throw new Error(action + '() requires a callback');
            }

            if (msg.args.length >= fn.length) {
                // the argument just before the callback must be a timeout
                timeout = msg.args.pop();
            }

            // if it's still as long or longer than fn.length we have too
            // many arguments
            if (msg.args.length >= fn.length) {
                throw new Error('Too many arguments passed to ' + action + '()');
            }

            // assign the action
            msg.action = action;

            // generate the callback id
            msg.id = [action].concat(process.hrtime(), Math.ceil(Math.random()*100000) ).join('|');

            // save the callback on our queue
            console.log('Setting listener for', msg.id);

            function resolveCb () {
                // call the actual callback at the end of this trn of the event loop
                var args = [].slice.call(arguments);
                args.unshift(cb);
                setImmediate.apply(null, args);

                // clean up the pending key and possibly unref() the keepAlive timer
                delete pending[msg.id];
                checkPending();
            }

            // make sure we have a pending key and are ref()'ed
            pending[msg.id] = true;
            checkPending();

            // listen for the response
            child.once(
                'message',
                childResponseListener.bind(
                    null,
                    msg.id,
                    (timeout >= 0?
                        timeoutOrCallback(
                            timeout,
                            action + '() timed out in '+ timeout + 'ms',
                            resolveCb
                        ) :
                        resolveCb
                    )
                )
            );

            // send a message to our child process
            child.send(msg);

        };
        return exported;
    }, target);

}

if (
    module === process.mainModule &&
    process.argv[2] === 'child' &&
    process.argv[3] === envPrefix &&
    'function' == typeof process.send
) {
    return setupChildProcess();
} else {
    return module.exports = setupRk8Pki.bind(null, module.exports);
}
