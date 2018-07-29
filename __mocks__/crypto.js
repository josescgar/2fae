const crypto = jest.genMockFromModule('crypto');

crypto.createCipheriv
  .mockReturnValue(({
    update: buffer => Buffer.from(buffer),
    final: () => Buffer.alloc(0),
    getAuthTag: () => Buffer.alloc(16),
  }));

crypto.createDecipheriv
  .mockReturnValue(({
    update: buffer => Buffer.from(buffer),
    final: () => Buffer.alloc(0),
    setAuthTag: () => undefined,
  }));

crypto.pbkdf2Sync
  .mockImplementation((key, salt, it, size) => Buffer.alloc(size));

crypto.randomBytes = size => Buffer.alloc(size);

module.exports = crypto;
