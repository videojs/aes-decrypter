/**
 * @file decrypter.js
 *
 * An asynchronous implementation of AES-128 CBC decryption with
 * PKCS#7 padding.
 */

import AES from './aes';
import {unpad} from 'pkcs7';

var crypto = window.crypto || window.msCrypto;
var subtle = crypto.subtle || msCrypto.subtle;

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
 * @param {Uint8Array} encrypted the encrypted bytes
 * @param {Uint32Array} key the bytes of the decryption key
 * @param {Uint32Array} initVector the initialization vector (IV) to
 * use for the first round of CBC.
 * @return {Uint8Array} the decrypted bytes
 *
 * @see http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * @see http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
 * @see https://tools.ietf.org/html/rfc2315
 */
export const decrypt = function(encrypted, key, initVector) {
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

/**
 * The `Decrypter` class that manages decryption of AES
 * data through `AsyncStream` objects and the `decrypt`
 * function
 *
 * @param {Uint8Array} encrypted the encrypted bytes
 * @param {Uint32Array} key the bytes of the decryption key
 * @param {Uint32Array} initVector the initialization vector (IV) to
 * @param {Function} done the function to run when done
 * @class Decrypter
 */
export class Decrypter {
  constructor(encrypted, key, initVector, done) {
/*  // Experimental mscrypto schmutz
    let initVector2 = new Uint8Array(initVector.buffer);
    let key2 = new Uint8Array(key.buffer);

    let i = 0;
    let algo = { name: 'AES-CBC', length: 128, iv: initVector2 };

    let keyOp = subtle.importKey('raw', key2, algo, ['decrypt']);
    keyOp.oncomplete = function(e) {
      let keyObj = e.target.result;
      let decrypt = subtle.decrypt(algo, keyObj);

      console.log('key result', e);

      decrypt.oncomplete = function(e) {
        console.log('decrypt result', e);

        if (!e.target.result) {
          console.log('no results from crypto');
        }

        done(null, new Uint8Array(e.target.result));
      };
      decrypt.onerror = console.log.bind(console, 'decrypt error');
      decrypt.onabort = console.log.bind(console, 'decrypt abort');
      decrypt.process(encrypted);
      decrypt.finish();
    };
    keyOp.onerror = console.log.bind(console, 'key error');
    keyOp.onabort = console.log.bind(console, 'key abort');
*/
    done(null, unpad(decrypt(encrypted, key, initVector)));
  }
}

export default {
  Decrypter,
  decrypt
};
