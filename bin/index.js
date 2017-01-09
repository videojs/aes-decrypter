#!/usr/bin/env node
'use strict';

let Decrypter = require('../').Decrypter;
let commander = require('commander');
let fs = require('fs');
let path = require('path');

let parseIV = (opt) => {
  let ivContent;
  let ivPath = path.resolve(opt);

  if (fs.existsSync(ivPath)) {
    ivContent = fs.readFileSync(ivPath).toString();
  } else {
    ivContent = opt;
  }
  let ints = ivContent.match(/^0?x?(.{8})(.{8})(.{8})(.{8})/i);

  let iv = new Uint32Array([
    parseInt(ints[1], 16),
    parseInt(ints[2], 16),
    parseInt(ints[3], 16),
    parseInt(ints[4], 16)
  ]);

  return iv;
};

commander
  .usage('[options] <input file> [output file]')
  .option('-k, --key <n>', 'The keyfile')
  .option('-i, --iv <n>', 'The initialization vector (256bit hex-string) or a file containing an IV', parseIV)
  .parse(process.argv);

if (commander.args.length < 1 ||
    typeof commander.key === undefined ||
    typeof commander.iv === undefined) {
  commander.outputHelp();
  process.exit(1);
}

let keyContent = fs.readFileSync(path.resolve(commander.key));
let encryptedBytes = fs.readFileSync(path.resolve(commander.args[0]));

let key = new Uint32Array([
  keyContent.readUInt32BE(0),
  keyContent.readUInt32BE(4),
  keyContent.readUInt32BE(8),
  keyContent.readUInt32BE(12)
]);

/* eslint-disable no-new */
new Decrypter(
  new Uint8Array(encryptedBytes),
  key,
  commander.iv,
  function(err, decryptedBytes) {
    // err always null
    if (!err) {
      let data = new Buffer(decryptedBytes);

      if (commander.args.length > 1) {
        // If we have a filename to write to, do it
        fs.writeFileSync(path.resolve(commander.args[1]), data);
      } else {
        // Otherwise, just output the data to stdout
        process.stdout.write(data);
      }
    }
  });
