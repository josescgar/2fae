const EncryptionMode = {
  AES_256_GCM: 0x00,
};

const FileFlags = {
  HEADER: '2fae',
  END_OF_FILENAME: '2faefded',
};

const MAX_SUPPORTED_FORMAT_VERSION = 0;

module.exports = {
  EncryptionMode,
  FileFlags,
  MAX_SUPPORTED_FORMAT_VERSION,
};
