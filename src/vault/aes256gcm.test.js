jest.mock('crypto');

const crypto = require('crypto');
const aes256gcm = require('./aes256gcm');

describe('AES 256 GCM encryption mode', () => {
  describe('encrypt method', () => {
    it('should encrypt using aes-256-gcm method', () => {
      const rawBuffer = Buffer.from('This is not encrypted!');
      const masterKey = 'fistro pecador de la pradera';

      aes256gcm.encrypt(rawBuffer, masterKey);
      expect(crypto.createCipheriv).toHaveBeenLastCalledWith(
        'aes-256-gcm',
        expect.any(Buffer),
        expect.any(Buffer),
      );
    });

    it('should use PBDKDF2 key derivation function', () => {
      const rawBuffer = Buffer.from('This is not encrypted!');
      const masterKey = 'Cuatro caballos van para bonanza';

      aes256gcm.encrypt(rawBuffer, masterKey);
      expect(crypto.pbkdf2Sync).toHaveBeenLastCalledWith(
        masterKey,
        expect.any(Buffer),
        expect.any(Number),
        32,
        'sha512',
      );
    });

    it('should return the generated key data', () => {
      const rawBuffer = Buffer.from('This is not encrypted!');
      const masterKey = 'Condemorl!';

      const res = aes256gcm.encrypt(rawBuffer, masterKey);

      expect(res.keyData).toEqual({
        key: expect.any(String),
        iv: expect.any(String),
        tag: expect.any(String),
      });

      expect(Buffer.from(res.keyData.key, 'hex')).toHaveLength(32);
      expect(Buffer.from(res.keyData.iv, 'hex')).toHaveLength(16);
      expect(Buffer.from(res.keyData.tag, 'hex')).toHaveLength(16);
    });

    it('should return encrypted data', () => {
      const rawBuffer = Buffer.from('This is not encrypted!');
      const masterKey = 'Condemorl!';

      const res = aes256gcm.encrypt(rawBuffer, masterKey);
      expect(Buffer.isBuffer(res.data)).toBe(true);
      expect(res.data).toHaveLength(rawBuffer.length);
    });

    it('should throw an error if no master key is provided', () => {
      expect(() => aes256gcm.encrypt(Buffer.from('something')))
        .toThrowError('No master key specified');
    });

    it('should throw an error if no buffer is provided', () => {
      expect(() => aes256gcm.encrypt(undefined, 'some key'))
        .toThrowError('No input buffer provided');
    });
  });

  describe('decrypt method', () => {
    const keyData = {
      iv: 'a9ea805d8bc8db32add6ee3d010a6a1a',
      key: 'd1b69293346c4b68519adfe9a600d198e8a2c274bc3169d57c1e792457de37da',
      tag: '9013ead22cd39f7df34840e04dbdc40d',
    };

    it('should decrypt the data using the aes-256-gcm method', () => {
      const encrypted = Buffer.from('mangled data');

      aes256gcm.decrypt(encrypted, keyData);
      expect(crypto.createDecipheriv).toHaveBeenLastCalledWith(
        'aes-256-gcm',
        Buffer.from(keyData.key, 'hex'),
        Buffer.from(keyData.iv, 'hex'),
      );
    });

    it('should return the decrypted data', () => {
      const encrypted = Buffer.from('more mangled data');

      const res = aes256gcm.decrypt(encrypted, keyData);
      expect(Buffer.isBuffer(res)).toBe(true);
      expect(res.length).toBe(encrypted.length);
    });

    it('should throw an error if no data buffer is provided', () => {
      expect(() => aes256gcm.decrypt(undefined, keyData))
        .toThrowError('No input data buffer provided');
    });

    it('should validate that the IV is present and of correct length', () => {
      const encrypted = Buffer.from('aaand more mangled data');

      let keys = { ...keyData, iv: undefined };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('IV not provided or different size from 16 bytes');

      keys = { ...keyData, iv: 'a9ea805d8bc8010a6a1a' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('IV not provided or different size from 16 bytes');

      keys = { ...keyData, iv: '' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('IV not provided or different size from 16 bytes');

      keys = { ...keyData, iv: 'a9ea805d8bc8db32add6ee3d010a6a1affff' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('IV not provided or different size from 16 bytes');

      keys = { ...keyData, iv: 12543 };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('IV not provided or different size from 16 bytes');
    });

    it('should validate that the key is present and of correct length', () => {
      const encrypted = Buffer.from('aaand more mangled data');

      let keys = { ...keyData, key: undefined };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Key not provided or different size from 32 bytes');

      keys = { ...keyData, key: 'd1b69293346c4b68519adfe9a600d19c1e792457de37da' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Key not provided or different size from 32 bytes');

      keys = { ...keyData, key: '' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Key not provided or different size from 32 bytes');

      keys = { ...keyData, key: 'd1b69293346c4b68519adfe9a600d198e8a2c274bc3169d57c1e792457de37daffff' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Key not provided or different size from 32 bytes');

      keys = { ...keyData, key: 12543 };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Key not provided or different size from 32 bytes');
    });

    it('should validate that the authentication tag is present and of correct length', () => {
      const encrypted = Buffer.from('aaand more mangled data');

      let keys = { ...keyData, tag: undefined };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Auth tag not provided or different size from 16 bytes');

      keys = { ...keyData, tag: 'a9ea805d8bc8010a6a1a' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Auth tag not provided or different size from 16 bytes');

      keys = { ...keyData, tag: '' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Auth tag not provided or different size from 16 bytes');

      keys = { ...keyData, tag: 'a9ea805d8bc8db32add6ee3d010a6a1affff' };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Auth tag not provided or different size from 16 bytes');

      keys = { ...keyData, tag: 12543 };
      expect(() => aes256gcm.decrypt(encrypted, keys))
        .toThrowError('Auth tag not provided or different size from 16 bytes');
    });
  });
});
