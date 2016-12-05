/**
 * @file decrypter.js
 *
 * An asynchronous implementation of AES-128 CBC decryption with
 * PKCS#7 padding.
 */

import window from 'global/window';
import AES from './aes';
import {unpad} from 'pkcs7';
import AsyncStream from './async-stream';
import Promise from 'promiz';

// Need to make the Promise polyfill global from a node-style import
// because the webcrypto library isn't really a node-style library
window.Promise = window.Promise || Promise;

let webcrypto = require('webcrypto-shim-jon');

/**
 * Convert network-order (big-endian) bytes into their little-endian
 * representation.
 */
const ntoh = function(word) {
  return (word << 24) |
    ((word & 0xff00) << 8) |
    ((word & 0xff0000) >> 8) |
    (word >>> 24);
};

/**
 * Decrypt bytes using AES-128 with CBC and PKCS#7 padding.
 *
 * @param {Uint32Array}  encrypted the encrypted bytes
 * @param {Uint32Array} key the bytes of the decryption key
 * @param {Uint32Array} initVector the initialization vector (IV) to
 * use for the first round of CBC.
 * @return {Uint8Array} the decrypted bytes
 *
 * @see http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * @see http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
 * @see https://tools.ietf.org/html/rfc2315
 */
const decryptNonNative = function(encrypted, key, initVector) {
  // word-level access to the encrypted bytes
  let encrypted32 = new Int32Array(encrypted.buffer,
                                   encrypted.byteOffset,
                                   encrypted.byteLength >> 2);
  let decipher = new AES(Array.prototype.slice.call(key));
  // byte and word-level access for the decrypted output
  let decrypted = new Uint8Array(encrypted.byteLength);
  let decrypted32 = new Int32Array(decrypted.buffer);

  // temporary variables for working with the IV, encrypted, and
  // decrypted data
  let init0;
  let init1;
  let init2;
  let init3;
  let encrypted0;
  let encrypted1;
  let encrypted2;
  let encrypted3;

  // iteration variable
  let wordIx;

  // pull out the words of the IV to ensure we don't modify the
  // passed-in reference and easier access
  init0 = initVector[0];
  init1 = initVector[1];
  init2 = initVector[2];
  init3 = initVector[3];

  // decrypt four word sequences, applying cipher-block chaining (CBC)
  // to each decrypted block
  for (wordIx = 0; wordIx < encrypted32.length; wordIx += 4) {
    // convert big-endian (network order) words into little-endian
    // (javascript order)
    encrypted0 = ntoh(encrypted32[wordIx]);
    encrypted1 = ntoh(encrypted32[wordIx + 1]);
    encrypted2 = ntoh(encrypted32[wordIx + 2]);
    encrypted3 = ntoh(encrypted32[wordIx + 3]);

    // decrypt the block
    decipher.decrypt(encrypted0,
                     encrypted1,
                     encrypted2,
                     encrypted3,
                     decrypted32,
                     wordIx);

    // XOR with the IV, and restore network byte-order to obtain the
    // plaintext
    decrypted32[wordIx] = ntoh(decrypted32[wordIx] ^ init0);
    decrypted32[wordIx + 1] = ntoh(decrypted32[wordIx + 1] ^ init1);
    decrypted32[wordIx + 2] = ntoh(decrypted32[wordIx + 2] ^ init2);
    decrypted32[wordIx + 3] = ntoh(decrypted32[wordIx + 3] ^ init3);

    // setup the IV for the next round
    init0 = encrypted0;
    init1 = encrypted1;
    init2 = encrypted2;
    init3 = encrypted3;
  }

  return decrypted;
};

const nativeDecrypter = function(encrypted, key, initVector) {
  let iv = new Uint8Array(initVector.buffer);

  let crypto = window.crypto;
  let algorithm = {name: 'AES-CBC', iv};
  let extractable = true;
  let usages = ['decrypt'];

  let keyPromise = crypto.subtle.importKey('raw', key, algorithm, extractable, usages);

  return keyPromise.then(function(importedKey) {
    return crypto.subtle.decrypt(algorithm, importedKey, encrypted);
  }).then(function(plaintextArrayBuffer) {
    return new Uint8Array(plaintextArrayBuffer);
  });
};

// 4 * 8000
const DECRYPTION_STEP = 32000;

const javascriptDecrypter = function(encrypted, key, initVector, done) {
  let view = new DataView(key.buffer);
  let littleEndianKey = new Uint32Array([
    view.getUint32(0),
    view.getUint32(4),
    view.getUint32(8),
    view.getUint32(12)
  ]);
  let step = DECRYPTION_STEP;
  let encrypted32 = new Int32Array(encrypted.buffer);
  let decrypted = new Uint8Array(encrypted.byteLength);
  let i = 0;

  let asyncStream = new AsyncStream();

  // split up the encryption job and do the individual chunks asynchronously
  asyncStream.push(decryptChunk(encrypted32.subarray(i, i + step),
                                littleEndianKey,
                                initVector,
                                decrypted));
  for (i = step; i < encrypted32.length; i += step) {
    initVector = new Uint32Array([ntoh(encrypted32[i - 4]),
                                  ntoh(encrypted32[i - 3]),
                                  ntoh(encrypted32[i - 2]),
                                  ntoh(encrypted32[i - 1])]);
    asyncStream.push(decryptChunk(encrypted32.subarray(i, i + step),
                                  littleEndianKey,
                                  initVector,
                                  decrypted));
  }
  // invoke the done() callback when everything is finished
  asyncStream.push(function() {
    // remove pkcs#7 padding from the decrypted bytes
    return done(null, unpad(decrypted));
  });
};

const decryptChunk = function(encrypted, key, initVector, decrypted) {
  return function() {
    // decryptNonNative must be a separate function (not a method or
    // static method on Decrypter) else IE10 will crash.
    let bytes = decryptNonNative(encrypted, key, initVector);

    decrypted.set(bytes, encrypted.byteOffset);
  };
};

const decrypter = function(encrypted, key, initVector, done) {
  nativeDecrypter(encrypted, key, initVector).then(function(decrypted) {
      return done(null, decrypted);
    },
    function(rejection) {
      return javascriptDecrypter(encrypted, key, initVector, done);
    });
};

export default decrypter;
