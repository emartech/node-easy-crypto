'use strict';

const crypto = require('crypto');
const config = require('./config');
const Key = require('./key');

class Crypto {
  _keyring;

  constructor(keyring) {
    this._keyring = keyring;
  }

  encrypt(plaintext) {
    return this._keyring.getKey()
      .then(key => this._encryptWithKey(key, plaintext));
  }

  decrypt(ciphertext) {
    return this._keyring.getKeyForCiphertext(ciphertext)
      .then(key => this._decryptWithKey(key, ciphertext));
  }

  _encryptWithKey(key, plaintext) {
    this._validateKeyType(key);
    return this._buildEncryptParameters(key, plaintext)
      .then(parameters => this._encryptWithParameters(parameters));
  }

  _decryptWithKey(key, ciphertext) {
    this._validateKeyType(key);
    return this._buildDecryptParameters(key, ciphertext)
      .then(parameters => this._decryptWithParameters(parameters));
  }

  _buildEncryptParameters(key, plaintext) {
    return this._getRandomBytes(config.IV_SIZE_IN_BYTES)
      .then(iv => {
        const encryptObject = this._createEncryptKeyObject(plaintext, iv, key);
        return Promise.resolve(encryptObject);
      });
  }

  _encryptWithParameters(parameters) {
    try {
      const encrypted = this._encryptRaw(parameters);
      const encodedCiphertext = Buffer.concat([parameters.salt, encrypted]).toString(config.CIPHERTEXT_ENCODING);
      return Promise.resolve(encodedCiphertext);
    } catch(ex) {
      return Promise.reject(ex);
    }
  }

  _buildDecryptParameters(key, ciphertext) {
    const rawCiphertext = Buffer.from(ciphertext, config.CIPHERTEXT_ENCODING);
    const slicedRawData = this._sliceCiphertext(rawCiphertext);
    return this._createDecryptKeyObject(slicedRawData, key.key);
  }

  _decryptWithParameters(parameters){
    try {
      const decrypted = this._decryptRaw(parameters);
      return Promise.resolve(decrypted.toString(config.PLAINTEXT_ENCODING));
    } catch(ex) {
      return Promise.reject(ex);
    }
  }

  _encryptRaw(encryptionParameters) {
    const cipher = crypto.createCipheriv(config.ENCRYPTION_MODE, encryptionParameters.key, encryptionParameters.iv);
    const encrypted = cipher.update(encryptionParameters.rawPlaintext);
    return Buffer.concat([encryptionParameters.iv, encrypted, cipher.final(), cipher.getAuthTag()]);
  }

  _decryptRaw(decryptionParameters) {
    const decipher = crypto.createDecipheriv(config.ENCRYPTION_MODE, decryptionParameters.key, decryptionParameters.iv);
    decipher.setAuthTag(decryptionParameters.tag);

    const decrypted = decipher.update(decryptionParameters.encrypted);

    return Buffer.concat([decrypted, decipher.final()]);
  }

  _createEncryptKeyObject(plaintext, iv, keyAndSalt) {
    const salt = keyAndSalt.salt;
    const key = keyAndSalt.key;
    const rawPlaintext = Buffer.from(plaintext, config.PLAINTEXT_ENCODING);
    return { iv, salt, rawPlaintext, key };
  }

  _createDecryptKeyObject(slicedRawData, key) {
    const iv = slicedRawData.iv;
    const encrypted = slicedRawData.encrypted;
    const tag = slicedRawData.tag;
    const keyObject = { iv, encrypted, tag, key };
    return Promise.resolve(keyObject)
  }

  _getRandomBytes(length) {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(length, (err, bytes) => {
        if (err) return reject(err);
        return resolve(bytes);
      });
    });
  }

  _sliceCiphertext(ciphertext) {
    this._validateCiphertextMinLength(ciphertext);

    const ivEndIndex = this._keyring.passwordSaltSize + config.IV_SIZE_IN_BYTES;
    const authTagStartIndex = ciphertext.length - config.AUTH_TAG_LENGTH_IN_BYTES;

    return {
      passwordSalt: ciphertext.slice(0, this._keyring.passwordSaltSize),
      iv: ciphertext.slice(this._keyring.passwordSaltSize, ivEndIndex),
      encrypted: ciphertext.slice(ivEndIndex, authTagStartIndex),
      tag: ciphertext.slice(authTagStartIndex, ciphertext.length)
    };
  }

  _validateCiphertextMinLength(ciphertext) {
    const minimumCiphertextSize = this._keyring.passwordSaltSize + config.IV_SIZE_IN_BYTES + config.AUTH_TAG_LENGTH_IN_BYTES + 1;
    if (minimumCiphertextSize > ciphertext.length) {
      throw new Error('Ciphertext must be at least ' + minimumCiphertextSize + ' bytes long.');
    }
  }

  _validateKeyType(key) {
    if (!(key instanceof Key)) {
      throw new TypeError('Key must be an Object returned by generateKey.');
    }
  }
}

module.exports = Crypto;
