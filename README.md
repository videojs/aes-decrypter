# decrypter



## Table of Contents

<!-- START doctoc -->
<!-- END doctoc -->
## Installation

```sh
npm install --save aes-decrypter
```

Also available to install globally:

```sh
npm install --global aes-decrypter
```

The npm installation is preferred, but Bower works, too.

```sh
bower install  --save aes-decrypter
```

## Usage

To include decrypter on your website or npm application, use any of the following methods.
```js
var Decrypter = require('aes-decrypter').Decrypter;
var fs = require('fs');
var keyContent = fs.readFileSync('something.key');
var encryptedBytes = fs.readFileSync('somithing.txt');

// keyContent is a string of the aes-keys content
var keyContent = fs.readFileSync(keyFile);

var view = new DataView(keyContent.buffer);
var key.bytes = new Uint32Array([
  view.getUint32(0),
  view.getUint32(4),
  view.getUint32(8),
  view.getUint32(12)
]);

key.iv = new Uint32Array([
  0, 0, 0, 0
]);

var d = new Decrypter(
  encryptedBytes,
  key.bytes,
  key.iv,
  function(err, decryptedBytes) {
    // err always null
});
```

## Command Line Usage

Using this module as a command is as easy as:
```bash
$ aes-decrypter
  Usage: aes-decrypter [options] <input file> [output file]

  Options:

    -h, --help     output usage information
    -k, --key <n>  The keyfile
    -i, --iv <n>   The initialization vector (0x<256bit hex string>) or a file containing an IV
```

Examples:
```bash
# Decrypt encrypted.bin with a keyfile and an initialization vector provided
# on the command-line saving the output to decrypted.bin
aes-decrypter -k encrypted.key -i 0x00000000000000000000000000000001 encrypted.bin decrypted.bin

# Decrypt encrypted.bin with a keyfile and an initialization vector file
# outputing the data to stdout
aes-decrypter -k encrypted.key -i encrypted.iv encrypted.bin
```

## License

Apache-2.0. Copyright (c) Brightcove, Inc.

