// see docs/hlse.md for instructions on how test data was generated
import QUnit from 'qunit';
import sinon from 'sinon';
import {decrypt, Decrypter, AsyncStream} from '../src';

// see docs/hlse.md for instructions on how test data was generated
const stringFromBytes = function(bytes) {
  let result = '';

  for (let i = 0; i < bytes.length; i++) {
    result += String.fromCharCode(bytes[i]);
  }
  return result;
};

const bytesToASCIIString = function(bytes) {
  return String.fromCharCode.apply(null, new Uint8Array(bytes));
};

QUnit.module('Decryption');

QUnit.test('decrypts a single AES-128 with PKCS7 block', function(assert) {
  const done = assert.async();

  assert.expect(1);

  const key = new Uint8Array(16);
  const iv = key;
  // the string "howdy folks" encrypted
  const encrypted = new Uint8Array([
    0xce, 0x90, 0x97, 0xd0,
    0x08, 0x46, 0x4d, 0x18,
    0x4f, 0xae, 0x01, 0x1c,
    0x82, 0xa8, 0xf0, 0x67
  ]);

  // Run native WebCrypto when available.
  decrypt(encrypted, key, iv, function(err, result) {
    if (err) {
      assert.notOk(true, 'Non-null error.');
    }
    assert.deepEqual(bytesToASCIIString(result),
                     'howdy folks',
                     'decrypted with a byte array key'
                    );
    done();
  });
});

QUnit.test('decrypts multiple AES-128 blocks with CBC', function(assert) {
  const key = new Uint8Array(16);
  const initVector = key;
  // the string "0123456789abcdef01234" encrypted
  const encrypted = new Uint8Array([
    0x14, 0xf5, 0xfe, 0x74,
    0x69, 0x66, 0xf2, 0x92,
    0x65, 0x1c, 0x22, 0x88,
    0xbb, 0xff, 0x46, 0x09,

    0x0b, 0xde, 0x5e, 0x71,
    0x77, 0x87, 0xeb, 0x84,
    0xa9, 0x54, 0xc2, 0x45,
    0xe9, 0x4e, 0x29, 0xb3
  ]);
  const done = assert.async();

  assert.expect(1);

  // Runs native WebCrypto when available.
  decrypt(encrypted, key, initVector, function(err, result) {
    if (err) {
      assert.notOk(true, 'Non-null error.');
    }
    assert.deepEqual(stringFromBytes(result),
                     '0123456789abcdef01234',
                     'decrypted multiple blocks'
                    );
    done();
  });
});

QUnit.test('decrypts a full segment', function(assert) {
  const key = new Uint8Array(16);
  const initVector = key;
  // the string "0123456789abcdef01234" encrypted
  const encrypted = new Uint8Array([
    0x14, 0xf5, 0xfe, 0x74,
    0x69, 0x66, 0xf2, 0x92,
    0x65, 0x1c, 0x22, 0x88,
    0xbb, 0xff, 0x46, 0x09,

    0x0b, 0xde, 0x5e, 0x71,
    0x77, 0x87, 0xeb, 0x84,
    0xa9, 0x54, 0xc2, 0x45,
    0xe9, 0x4e, 0x29, 0xb3
  ]);
  const done = assert.async();

  assert.expect(1);

  // Runs native WebCrypto when available.
  decrypt(encrypted, key, initVector, function(err, result) {
    if (err) {
      assert.notOk(true, 'Non-null error.');
    }
    assert.deepEqual(stringFromBytes(result),
                     '0123456789abcdef01234',
                     'decrypted multiple blocks'
                    );
    done();
  });
});

QUnit.test(
  'verify that the deepcopy works by doing two decrypts in the same test',
  function(assert) {
    assert.expect(2);

    const done = assert.async(2);
    const key = new Uint8Array(16);
    const initVector = key;

    // the string "howdy folks" encrypted
    const pkcs7Block = new Uint8Array([
      0xce, 0x90, 0x97, 0xd0,
      0x08, 0x46, 0x4d, 0x18,
      0x4f, 0xae, 0x01, 0x1c,
      0x82, 0xa8, 0xf0, 0x67
    ]);

    // Runs native WebCrypto when available.
    decrypt(pkcs7Block, key, initVector, function(err, result) {
      if (err) {
        assert.notOk(true, 'Non-null error.');
      }
      assert.deepEqual(stringFromBytes(result),
                       'howdy folks',
                       'decrypted with a byte array key'
                      );
      done();
    });

    // the string "0123456789abcdef01234" encrypted
    const cbcBlocks = new Uint8Array([
      0x14, 0xf5, 0xfe, 0x74,
      0x69, 0x66, 0xf2, 0x92,
      0x65, 0x1c, 0x22, 0x88,
      0xbb, 0xff, 0x46, 0x09,

      0x0b, 0xde, 0x5e, 0x71,
      0x77, 0x87, 0xeb, 0x84,
      0xa9, 0x54, 0xc2, 0x45,
      0xe9, 0x4e, 0x29, 0xb3
    ]);

    // Runs native WebCrypto when available.
    decrypt(cbcBlocks, key, initVector, function(err, result) {
      if (err) {
        assert.notOk(true, 'Non-null error.');
      }
      assert.deepEqual(stringFromBytes(result),
                       '0123456789abcdef01234',
                       'decrypted multiple blocks'
                      );
      done();
    });
  }
);

QUnit.test('asynchronously decrypts a 4-word block', function(assert) {
  assert.expect(1);

  const done = assert.async();
  const key = new Uint8Array(16);
  const initVector = new Uint32Array(4);
  // the string "howdy folks" encrypted
  const encrypted = new Uint8Array([0xce, 0x90, 0x97, 0xd0,
                                  0x08, 0x46, 0x4d, 0x18,
                                  0x4f, 0xae, 0x01, 0x1c,
                                  0x82, 0xa8, 0xf0, 0x67]);
  /* eslint-disable no-unused-vars */

  // Runs non-native JavaScript AES-CBC decryption always, even if
  // WebCrypto is available.
  const decrypter = new Decrypter(encrypted,
                                key,
                                initVector,
                                function(err, result) {
                                  if (err) {
                                    assert.notOk(true, 'Non-null error.');
                                  }
                                  assert.deepEqual(
                                    stringFromBytes(result),
                                    'howdy folks',
                                    'decrypts and unpads the result'
                                  );
                                  done();
                                });
  /* eslint-enable no-unused-vars */
});

QUnit.module('Incremental Processing', {
  beforeEach() {
    this.clock = sinon.useFakeTimers();
  },
  afterEach() {
    this.clock.restore();
  }
});

QUnit.test('executes a callback after a timeout', function(assert) {
  const asyncStream = new AsyncStream();
  let calls = '';

  asyncStream.push(function() {
    calls += 'a';
  });

  this.clock.tick(asyncStream.delay);
  assert.equal(calls, 'a', 'invoked the callback once');
  this.clock.tick(asyncStream.delay);
  assert.equal(calls, 'a', 'only invoked the callback once');
});

QUnit.test('executes callback in series', function(assert) {
  const asyncStream = new AsyncStream();
  let calls = '';

  asyncStream.push(function() {
    calls += 'a';
  });
  asyncStream.push(function() {
    calls += 'b';
  });

  this.clock.tick(asyncStream.delay);
  assert.equal(calls, 'a', 'invoked the first callback');
  this.clock.tick(asyncStream.delay);
  assert.equal(calls, 'ab', 'invoked the second');
});

QUnit.module('Incremental Decryption', {
  beforeEach() {
    this.clock = sinon.useFakeTimers();
  },
  afterEach() {
    this.clock.restore();
  }
});

QUnit.test('breaks up input greater than the step value', function(assert) {
  const encrypted = new Int32Array(Decrypter.STEP + 4);
  let done = false;

  // Runs non-native JavaScript AES-CBC decryption always, even if
  // WebCrypto is available.
  const decrypter = new Decrypter(encrypted,
                                  new Uint8Array(16),
                                  new Uint32Array(4),
                                  function() {
                                    done = true;
                                  });

  this.clock.tick(decrypter.asyncStream_.delay * 2);
  assert.ok(!done, 'not finished after two ticks');

  this.clock.tick(decrypter.asyncStream_.delay);
  assert.ok(done, 'finished after the last chunk is decrypted');
});
