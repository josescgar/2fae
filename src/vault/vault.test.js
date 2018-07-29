const { EncryptionMode } = require('../constants');
const vault = require('./vault');

jest.mock('./aes256gcm');
const aes256gcm = require('./aes256gcm');

describe('Vault service', () => {
  beforeEach(() => {
    aes256gcm.encrypt.mockReset();
    aes256gcm.decrypt.mockReset();
  });

  describe('encrypt method', () => {
    it('should encrypt using aes256gcm if no mode specified', () => {
      const someBuffer = Buffer.from('buff');
      const masterKey = 'someMasterKey';

      vault.encrypt(someBuffer, masterKey);

      expect(aes256gcm.encrypt).toHaveBeenCalledTimes(1);
      expect(aes256gcm.encrypt).toHaveBeenLastCalledWith(someBuffer, masterKey);
    });

    it('should encrypt using aes256gcm if mode not supported', () => {
      const someBuffer = Buffer.from('buff');
      const masterKey = 'someMasterKey';

      vault.encrypt(someBuffer, masterKey, 'some-weird-mode');

      expect(aes256gcm.encrypt).toHaveBeenCalledTimes(1);
      expect(aes256gcm.encrypt).toHaveBeenLastCalledWith(someBuffer, masterKey);
    });

    it('should encrypt using aes256gcm if specified', () => {
      const someBuffer = Buffer.from('buff');
      const masterKey = 'someMasterKey';

      vault.encrypt(someBuffer, masterKey, EncryptionMode.AES_256_GCM);

      expect(aes256gcm.encrypt).toHaveBeenCalledTimes(1);
      expect(aes256gcm.encrypt).toHaveBeenLastCalledWith(someBuffer, masterKey);
    });

    it('should return whatever the encryption mode returns', () => {
      const someBuffer = Buffer.from('buff');
      const masterKey = 'someMasterKey';
      const someEncryptedResult = {
        data: Buffer.from('encrypteddata'),
        keyData: {
          iv: 'something',
        },
      };

      aes256gcm.encrypt.mockReturnValue(someEncryptedResult);

      const res = vault.encrypt(someBuffer, masterKey, EncryptionMode.AES_256_GCM);
      expect(res).toBe(someEncryptedResult);
    });
  });

  describe('decrypt method', () => {
    it('should decrypt using aes256gcm if no mode specified', () => {
      const keyData = { iv: 'someIV', key: 'someKey' };
      const someEncryptedBuffer = Buffer.from('encrypted data');

      vault.decrypt(someEncryptedBuffer, keyData);

      expect(aes256gcm.decrypt).toHaveBeenCalledTimes(1);
      expect(aes256gcm.decrypt).toHaveBeenCalledWith(someEncryptedBuffer, keyData);
    });

    it('should decrypt using aes256gcm if mode not supported', () => {
      const keyData = { iv: 'someIV', key: 'someKey' };
      const someEncryptedBuffer = Buffer.from('encrypted data');

      vault.decrypt(someEncryptedBuffer, keyData, 'some-weird-mode');

      expect(aes256gcm.decrypt).toHaveBeenCalledTimes(1);
      expect(aes256gcm.decrypt).toHaveBeenCalledWith(someEncryptedBuffer, keyData);
    });

    it('should decrypt using aes256gcm if specified', () => {
      const keyData = { iv: 'someIV', key: 'someKey' };
      const someEncryptedBuffer = Buffer.from('encrypted data');

      vault.decrypt(someEncryptedBuffer, keyData, EncryptionMode.AES_256_GCM);

      expect(aes256gcm.decrypt).toHaveBeenCalledTimes(1);
      expect(aes256gcm.decrypt).toHaveBeenCalledWith(someEncryptedBuffer, keyData);
    });

    it('should return whatever the decryption mode returns', () => {
      const keyData = { iv: 'someIV', key: 'someKey' };
      const someEncryptedBuffer = Buffer.from('encrypted data');
      const someDecryptedBuffer = Buffer.from('some decrypted thing');

      aes256gcm.decrypt.mockReturnValue(someDecryptedBuffer);

      const res = vault.decrypt(someEncryptedBuffer, keyData, EncryptionMode.AES_256_GCM);
      expect(res).toBe(someDecryptedBuffer);
    });
  });
});
