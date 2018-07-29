const EncryptionMode = {
  AES_256_GCM: 0,
};

const FileFlags = {
  HEADER: '2FAE',
  END_OF_FILENAME: '2FAEFDED',
};

const FORMAT_EXTENSION = '2fae';

module.exports = {
  EncryptionMode,
  FileFlags,
  FORMAT_EXTENSION,
};
