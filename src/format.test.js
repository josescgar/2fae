const fs = require('fs');
const path = require('path');
const format = require('./format');
const { EncryptionMode } = require('./constants');

const fixturePath = path.join(__dirname, '..', '__fixtures__');
const expectedInput = require('../__fixtures__/expected');

const encryptedInput = fs.readFileSync(path.join(fixturePath, 'something-encrypted.2fae'));
const originalInput = fs.readFileSync(path.join(fixturePath, 'some-file.txt'));

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

  describe('getFileId method', () => {
    it('should return a string of the appropriate length', () => {
      const res = format.getFileId(encryptedInput);
      expect(res).toHaveLength(32);
      expect(res).toBe(expectedInput.fileId);
    });

    it('should throw an error if the first argument is not a buffer', () => {
      expect(() => format.getFileId('not a buffer'))
        .toThrowError('Expected a buffer as input');
    });
  });

  describe('decrypt method', () => {
    it('should throw an error if the input file is not a 2fae file', () => {
      const not2faeFile = Buffer.from(encryptedInput);
      not2faeFile[0] = 6;
      expect(() => format.decrypt(not2faeFile, expectedInput.keyData))
        .toThrowError('The input file is not a 2fae file');
    });

    it('should throw an error if the encryption mode is not supported', () => {
      const not2faeFile = Buffer.from(encryptedInput);
      not2faeFile[3] = 0xFF;
      expect(() => format.decrypt(not2faeFile, expectedInput.keyData))
        .toThrowError('Unrecognized encryption mode');
    });

    it('should return the original filename', () => {
      const res = format.decrypt(encryptedInput, expectedInput.keyData);
      expect(res.originalFilename).toBe(expectedInput.originalFilename);
    });

    it('should return the original file data without the filename or the filename end flag', () => {
      const res = format.decrypt(encryptedInput, expectedInput.keyData);
      expect(Buffer.isBuffer(res.fileData)).toBe(true);
      expect(encryptedInput.length).not.toBe(expectedInput.originalSize);
      expect(res.fileData).toHaveLength(expectedInput.originalSize);
    });
  });

  describe('encrypt method', () => {
    it('should throw an error if no input buffer provided', () => {
      expect(() => format.encrypt(undefined, 'some-file.txt', 'randomMasterKey'))
        .toThrowError('No input buffer to encrypt received');
    });

    it('should throw an error if no filename supplied', () => {
      expect(() => format.encrypt(originalInput, undefined, 'randomMasterKey'))
        .toThrowError('No original filename supplied');

      expect(() => format.encrypt(originalInput, null, 'randomMasterKey'))
        .toThrowError('No original filename supplied');

      expect(() => format.encrypt(originalInput, '', 'randomMasterKey'))
        .toThrowError('No original filename supplied');
    });

    it('should throw an error if no master key provided', () => {
      expect(() => format.encrypt(originalInput, 'some-file.txt', ''))
        .toThrowError('No master key provided');

      expect(() => format.encrypt(originalInput, 'some-file.txt', null))
        .toThrowError('No master key provided');

      expect(() => format.encrypt(originalInput, 'some-file.txt'))
        .toThrowError('No master key provided');
    });

    it('should return the key and file data', () => {
      const res = format.encrypt(originalInput, 'some-file.txt', 'someRandomKey');

      expect(res.keyData).toEqual(expect.any(Object));
      expect(Buffer.isBuffer(res.data)).toBe(true);
      expect(res.fileId).toEqual(expect.any(String));
      expect(res.fileId).toHaveLength(32);
    });

    it('should correctly encrypt the data', () => {
      const originalFilename = 'some-file.txt';
      const encrypted = format.encrypt(originalInput, originalFilename, 'someRandomKey');

      const decrypted = format.decrypt(encrypted.data, encrypted.keyData);

      expect(decrypted.originalFilename).toBe(originalFilename);
      expect(decrypted.fileData).toHaveLength(originalInput.length);
      expect(Buffer.compare(decrypted.fileData, originalInput)).toBe(0);
    });
  });
});
