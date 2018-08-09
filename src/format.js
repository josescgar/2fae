const { FileFlags, EncryptionMode } = require('./constants');
const vault = require('./vault/vault');

module.exports = {
  is2faeFile(inputBuffer) {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    return inputBuffer.slice(0, 2).toString('hex') === FileFlags.HEADER;
  },

  getFormatVersion(inputBuffer) {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    return parseInt(inputBuffer[2], 0);
  },

  getEncryptionMode(inputBuffer) {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    const mode = inputBuffer[3];
    if (!Object.values(EncryptionMode).some(knownMode => knownMode === mode)) {
      return null;
    }

    return mode;
  },

  getFileId(inputBuffer) {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw TypeError('Expected a buffer as input');
    }

    return inputBuffer.slice(4, 20).toString('hex');
  },

  decrypt(inputBuffer, keyData) {
    if (!this.is2faeFile(inputBuffer)) {
      throw new TypeError('The input file is not a 2fae file');
    }

    const mode = this.getEncryptionMode(inputBuffer);
    if (mode === null) {
      throw new TypeError('Unrecognized encryption mode');
    }

    const encryptedData = inputBuffer.slice(20);
    const decryptedBuffer = vault.decrypt(encryptedData, keyData, mode);
    const filenameEndTag = decryptedBuffer.indexOf(FileFlags.END_OF_FILENAME, 0, 'hex');

    return {
      originalFilename: decryptedBuffer.slice(0, filenameEndTag).toString(),
      fileData: decryptedBuffer.slice(filenameEndTag + 4),
    };
  },
};
