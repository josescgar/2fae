const { FileFlags, EncryptionMode } = require('./constants');
const vault = require('./vault/vault');

module.exports = {
  is2faeFile: (inputBuffer) => {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    return inputBuffer.slice(0, 2).toString('hex') === FileFlags.HEADER;
  },

  getFormatVersion: (inputBuffer) => {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    return parseInt(inputBuffer[2], 0);
  },

  getEncryptionMode: (inputBuffer) => {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    const mode = inputBuffer[3];
    if (!Object.values(EncryptionMode).some(knownMode => knownMode === mode)) {
      return null;
    }

    return mode;
  },

  getFileId: (inputBuffer) => {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    return inputBuffer.slice(4, 20).toString('hex');
  },

  decrypt: (inputBuffer, keyData) => {
    if (!this.is2faeFile(inputBuffer)) {
      throw new TypeError('The input file is not a 2fae file');
    }

    const mode = this.getEncryptionMode(inputBuffer);
    if (!mode) {
      throw new TypeError('Unrecognized encryption mode');
    }

    return vault.decrypt(inputBuffer, keyData, mode);
  },
};
