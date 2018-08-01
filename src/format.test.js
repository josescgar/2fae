const fs = require('fs');
const path = require('path');
const format = require('./format');
const { FileFlags, EncryptionMode } = require('./constants');

const encryptedInput = fs.readFileSync(path.join(__dirname, '..', '__fixtures__', 'something-encrypted.2fae'));

describe('2fae service', () => {
  describe('is2faeFile method', () => {
    it('should return true if the file starts with the expected header', () => {
      expect(format.is2faeFile(encryptedInput)).toBe(true);
    });

    it('should return false if the file does not start with the expected header', () => {
      const fakeFile = Buffer.from(encryptedInput);
      fakeFile[0] = 5;

      expect(format.is2faeFile(fakeFile)).toBe(false);
    });

    it('should throw an error if the first argument is not a buffer', () => {
      expect(() => format.is2faeFile('not a buffer'))
        .toThrowError('Expected a buffer as input');
    });
  });

  describe('getFormatVersion method', () => {
    it('should return a version number', () => {
      expect(format.getFormatVersion(encryptedInput)).toBe(0);

      const otherVersion = Buffer.from(encryptedInput);
      otherVersion[2] = 0x09;
      expect(format.getFormatVersion(otherVersion)).toBe(9);

      otherVersion[2] = 0xFF;
      expect(format.getFormatVersion(otherVersion)).toBe(255);

      otherVersion[2] = 0xAA;
      expect(format.getFormatVersion(otherVersion)).toBe(170);
    });

    it('should throw an error if the first argument is not a buffer', () => {
      expect(() => format.getFormatVersion('not a buffer'))
        .toThrowError('Expected a buffer as input');
    });
  });

  describe('getEncryptionMode method', () => {
    it('should return the corresponding method if it is known', () => {
      expect(format.getEncryptionMode(encryptedInput))
        .toBe(EncryptionMode.AES_256_GCM);
    });

    it('should return null if the method is not recognized', () => {
      const otherMode = Buffer.from(encryptedInput);
      otherMode[3] = 0x03;
      expect(format.getEncryptionMode(otherMode)).toBeNull();
    });

    it('should throw an error if the first argument is not a buffer', () => {
      expect(() => format.getEncryptionMode('not a buffer'))
        .toThrowError('Expected a buffer as input');
    });
  });

  // describe('getFileId method', () => {
  //   it('should return a string of the appropiatte length');
  // });
  // describe('encrypt method');
  // describe('decrypt method');
});
