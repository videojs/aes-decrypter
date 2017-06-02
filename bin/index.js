#!/usr/bin/env node
'use strict';

const decrypt = require('../').decrypt;
const commander = require('commander');
const fs = require('fs');
const path = require('path');

const parseIV = (opt) => {
  let ivContent;
  const ivPath = path.resolve(opt);

  if (fs.existsSync(ivPath)) {
    ivContent = fs.readFileSync(ivPath).toString();
  } else {
    ivContent = opt;
  }
  const ints = ivContent.match(/^0?x?(.{8})(.{8})(.{8})(.{8})/i);

  const iv = new Uint32Array([
    parseInt(ints[1], 16),
    parseInt(ints[2], 16),
    parseInt(ints[3], 16),
    parseInt(ints[4], 16)
  ]);

  return iv;
};

const parseKey = (opt) => {
  const keyPath = path.resolve(opt);

  if (fs.existsSync(keyPath)) {
    const keyContent = fs.readFileSync(keyPath);

    return new Uint8Array(keyContent);
  }

  const keyContent = opt;
  const ints = keyContent.match(/^0?x?(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})/i);

  return new Uint8Array([
    parseInt(ints[1], 16),
    parseInt(ints[2], 16),
    parseInt(ints[3], 16),
    parseInt(ints[4], 16),
    parseInt(ints[5], 16),
    parseInt(ints[6], 16),
    parseInt(ints[7], 16),
    parseInt(ints[8], 16),
    parseInt(ints[9], 16),
    parseInt(ints[10], 16),
    parseInt(ints[11], 16),
    parseInt(ints[12], 16),
    parseInt(ints[13], 16),
    parseInt(ints[14], 16),
    parseInt(ints[15], 16),
    parseInt(ints[16], 16)
  ]);
};

commander
  .usage('[options] <input file> [output file]')
  .option('-k, --key <n>', 'The keyfile as a 128bit hex-string or the path to a file containing the key in raw binary', parseKey)
  .option('-i, --iv <n>', 'The initialization vector as a 128bit hex-string or the path to a file containing a hex-string', parseIV)
  .parse(process.argv);

if (commander.args.length < 1 ||
    typeof commander.key === undefined ||
    typeof commander.iv === undefined) {
  commander.outputHelp();
  process.exit(1);
}

const encryptedBytes = fs.readFileSync(path.resolve(commander.args[0]));

decrypt(
  new Uint8Array(encryptedBytes),
  commander.key,
  commander.iv,
  function(err, decryptedBytes) {
    // err always null
    if (!err) {
      const data = new Buffer(decryptedBytes);

      if (commander.args.length > 1) {
        // If we have a filename to write to, do it
        fs.writeFileSync(path.resolve(commander.args[1]), data);
      } else {
        // Otherwise, just output the data to stdout
        process.stdout.write(data);
      }
    }
  });
