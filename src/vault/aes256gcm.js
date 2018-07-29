const crypto = require('crypto');

const parseInputKey = (key, expectedLenght) => {
  if (!key) {
    return false;
  }

  try {
    const buff = Buffer.from(key, 'hex');
    return ((buff.length === expectedLenght) && buff) || false;
  } catch (e) {
    return false;
  }
};

module.exports = {
  /**
   * Encrypts the given data buffer with aes-256-gcm encryption. Master key is used
   * to derive a more secure key using PBKDF2 key derivation.
   * @param {string|Buffer|DataView|TypedArray} rawBuffer Unencrypted data
   * @param {string|Buffer|DataView|TypedArray} masterKey
   *        User defined key used for generating encryption keys
   * @returns {{keyData: {iv: string, key: string, tag: string}, data: Buffer}}
   *          Generated IV, key and auth tag for encryption (HEX string) and encrypted data buffer
   */
  encrypt: (rawBuffer, masterKey) => {
    if (!masterKey) {
      throw new TypeError('No master key specified');
    }

    if (!rawBuffer) {
      throw new TypeError('No input buffer provided');
    }

    const iv = crypto.randomBytes(16);

    const salt = crypto.randomBytes(64);
    const key = crypto.pbkdf2Sync(masterKey, salt, 2145, 32, 'sha512');

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    const encrypted = Buffer.concat([cipher.update(rawBuffer), cipher.final()]);

    const tag = cipher.getAuthTag();

    return {
      keyData: {
        iv: iv.toString('hex'),
        key: key.toString('hex'),
        tag: tag.toString('hex'),
      },
      data: encrypted,
    };
  },

  /**
   * Decrypts the given data buffer using the given key information.
   * @param {string|Buffer|DataView|TypedArray} dataBuffer Encrypted data buffer
   * @param {{iv: string, key: string, tag: string}} keyData
   *        Cipher keys used for encryption and authentication in Hexadecimal
   * @returns {Buffer} Decrypted data
   */
  decrypt: (dataBuffer, { iv, key, tag }) => {
    if (!dataBuffer) {
      throw new TypeError('No input data buffer provided');
    }

    const keyHex = parseInputKey(key, 32);
    if (!keyHex) {
      throw new TypeError('Key not provided or different size from 32 bytes');
    }

    const ivHex = parseInputKey(iv, 16);
    if (!ivHex) {
      throw new TypeError('IV not provided or different size from 16 bytes');
    }

    const authTagHex = parseInputKey(tag, 16);
    if (!authTagHex) {
      throw new TypeError('Auth tag not provided or different size from 16 bytes');
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', keyHex, ivHex);
    decipher.setAuthTag(authTagHex);

    return Buffer.concat([decipher.update(dataBuffer), decipher.final()]);
  },
};
