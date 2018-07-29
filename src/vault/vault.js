const { EncryptionMode } = require('../constants');
const aes256gcm = require('./aes256gcm');

module.exports = {
  /**
   * Encrypts the given data buffer with the selected encryption mode
   * @param {Buffer} rawBuffer Data buffer to be encrypted
   * @param {string} masterKey Master key for encryption key derivation
   * @param {EncryptionMode} mode Encryption mode to be used. Defaults to aes-256-gcm.
   * @returns {{keyData: object, data: Buffer}} Encrypted data and keys used for encryption
   */
  encrypt: (rawBuffer, masterKey, mode = EncryptionMode.AES_256_GCM) => {
    switch (mode) {
      default:
        return aes256gcm.encrypt(rawBuffer, masterKey);
    }
  },

  /**
   * Decrypts the given buffer using the given decryption keys for the selected mode
   * @param {Buffer} dataBuffer Encrypted data buffer
   * @param {object} keyData Decryption keys. Specific to each encryption mode.
   * @param {EncryptionMode} mode Encryption mode used
   * @returns {Buffer} Decrypted data
   */
  decrypt: (dataBuffer, keyData, mode = EncryptionMode.AES_256_GCM) => {
    switch (mode) {
      default:
        return aes256gcm.decrypt(dataBuffer, keyData);
    }
  },
};
