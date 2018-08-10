const uuid = require('uuid');
const { FileFlags, EncryptionMode, MAX_SUPPORTED_FORMAT_VERSION } = require('./constants');
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

  encrypt(
    inputBuffer,
    filename,
    masterKey,
    mode = EncryptionMode.AES_256_GCM,
    version = MAX_SUPPORTED_FORMAT_VERSION,
  ) {
    if (!Buffer.isBuffer(inputBuffer)) {
      throw new TypeError('No input buffer to encrypt received');
    }

    if (!filename) {
      throw new TypeError('No original filename supplied');
    }

    if (!masterKey) {
      throw new TypeError('No master key provided');
    }

    const filenameBuffer = Buffer.from(filename);
    const filenameTagBuffer = Buffer.from(FileFlags.END_OF_FILENAME, 'hex');

    const rawBuffer = Buffer.concat([filenameBuffer, filenameTagBuffer, inputBuffer]);
    const encryptedData = vault.encrypt(rawBuffer, masterKey, mode);

    const headerDescriptor = Buffer.from(FileFlags.HEADER, 'hex');
    const versionDescriptor = Buffer.alloc(1, version, 'hex');
    const encModeDescriptor = Buffer.alloc(1, mode, 'hex');
    const fileId = uuid.v4().replace(/-/g, '');
    const fileIdDescriptor = Buffer.from(fileId, 'hex');

    const finalFile = Buffer.concat([
      headerDescriptor,
      versionDescriptor,
      encModeDescriptor,
      fileIdDescriptor,
      encryptedData.data,
    ]);

    return {
      data: finalFile,
      keyData: encryptedData.keyData,
      fileId,
    };
  },
};
