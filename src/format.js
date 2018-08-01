const { FileFlags, EncryptionMode } = require('./constants');

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
};
