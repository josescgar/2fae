# Two factor authentication encryption file format
![Travis CI](https://travis-ci.org/josescgar/2fae.svg?branch=master) [![Coverage Status](https://coveralls.io/repos/github/josescgar/2fae/badge.svg?branch=master)](https://coveralls.io/github/josescgar/2fae?branch=master)

This library provides capabilities for encrypting, decrypting and manipulating `.2fae` files.

2fae is a file format for adding two factor authentication to already encrypted files. This adds another layer of security to the encrypted file, making sure that only the intended recipients for the file are able to decrypt it, even if the file password is compromissed.

The file format by itself does not offer this functionality but rather is the container of the encrypted data as well as the metadata required by the 2fae client and server to carry out the encryption and decryption.

## Encryption/Decryption flows
When a user encrypts a file, the original file data is encrypted using `aes-256-gcm` encryption by default. At the same time that the encryption happens, a unique file id is generated and this information, together with the user id of the person carrying out the encryption, the encryption IV, key, auth tag, and file password are sent to the server. At the same time, a `2fae` file is generated, which contains only the encrypted data and the file id.

The server securely stores the decryption information relating them specificaly to the given file id and the user.

For decryption, the user needs to successfuly provide the file password and go through the two factor authentication process. If both are correct, the server then sends the decryption keys to the client and with this information, the original file is decrypted and restored.

## Format specification
`2fae` files content have the following format byte to byte.

- **Header**. *2 bytes (0-1)*. File header with a constant identifying this as a 2fae file. Should always have the value `2FAE` in hexadecimal.

- **Format version**. *1 byte (2)*. Version of the 2fae format. Hexadecimal number.

- **Encryption protocol**. *1 byte (3)*. Encryption protocol used for the file. Hexadecimal number.

- **File ID**. *16 bytes (4-19)*. Unique identifier for the file. 16 bytes hexadecimal UUID.

- **Encrypted data**. *n bytes (20-n)*. Original encrypted data. It also contains the original filename. Refer to the next section for more details on the content of the encrypted data.

### Encrypted content
The bytes 20 to n contains encrypted data. However, the encrypted data is not only the original file data but some additional information that is encrypted for safekeeping. After decryption, the data has the following format. For simplicity, byte counts starts at the beginning of the decrypted data.

- **Filename**. *k bytes (0-k)*. Original name of the file before it was encrypted. This can be used to restore it's original name and/or extension.

- **Filename end flag**. *4 bytes ((k+1)-(k+4))*. Flag to identify when the original filename finishes. This allows to account for variable lenght in the name. Always has the value `2FAEFDED` in hexadecimal.

- **Original data**. *n bytes ((k+5)-n)*. Original file data already decrypted.

## Caveats
The main drawback of 2fae is that files cannot be encrypted or decrypted without an internet connection since the actual decryption keys and the two factor authentication flow lives in the server.
