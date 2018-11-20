'use strict';

const crypto = require('crypto');
const Key = require('./key');

const DEFAULT_PASSWORD_SALT_SIZE_IN_BYTES = 12;
const DEFAULT_ITERATION_COUNT = 10000;
const IV_SIZE_IN_BYTES = 12;
const KEY_SIZE_IN_BITS = 256;
const KEY_SIZE_IN_BYTES = KEY_SIZE_IN_BITS / 8;
const ENCRYPTION_MODE = 'aes-' + KEY_SIZE_IN_BITS + '-gcm';
const HMAC_MODE = 'sha256';
const PLAINTEXT_ENCODING = 'utf-8';
const CIPHERTEXT_ENCODING = 'base64';
const AUTH_TAG_LENGTH_IN_BYTES = 16;

class Crypto {

  constructor(passwordSaltSize, iterationCount) {
    this._validateNumber(passwordSaltSize, 'passwordSaltSize');
    this._validateNumber(iterationCount, 'iterationCount');

    this._passwordSaltSize = passwordSaltSize;
    this._iterationCount = iterationCount;
  }

  encrypt(password, plaintext) {
    return this._getRandomBytes(this._passwordSaltSize)
      .then(salt => this.generateKey(password, salt))
      .then(key => this.encryptWithKey(key, plaintext));
  }

  decrypt(password, ciphertext) {
    const salt = this.getSaltFromEncrypted(ciphertext);
    return this.generateKey(password, salt)
      .then(key => this.decryptWithKey(key, ciphertext));
  }

  encryptWithKey(key, plaintext) {
    this._validateKeyType(key);
    return this._buildEncryptParameters(key, plaintext)
      .then(parameters => this._encryptWithParameters(parameters));
  }

  decryptWithKey(key, ciphertext) {
    this._validateKeyType(key);
    return this._buildDecryptParameters(key, ciphertext)
      .then(parameters => this._decryptWithParameters(parameters));
  }

  generateKey(password, salt) {
    this._validateBuffer(salt, 'Salt');
    this._validateSaltSize(salt);

    return new Promise((resolve, reject) => {
      return crypto.pbkdf2(
        password,
        salt,
        this._iterationCount,
        KEY_SIZE_IN_BYTES,
        HMAC_MODE,
        (err, key) => {
          if (err) return reject(err);
          return resolve(new Key(key, salt));
        }
      );
    });
  }

  generateSalt() {
    return this._getRandomBytes(this._passwordSaltSize);
  }

  getSaltFromEncrypted(encrypted) {
    const cipherText = Buffer.from(encrypted, CIPHERTEXT_ENCODING);
    return cipherText.slice(0, this._passwordSaltSize);
  }

  _buildEncryptParameters(key, plaintext) {
    return this._getRandomBytes(IV_SIZE_IN_BYTES)
      .then(iv => {
        const encryptObject = this._createEncryptKeyObject(plaintext, iv, key);
        return Promise.resolve(encryptObject);
      });
  }

  _encryptWithParameters(parameters) {
    try {
      const encrypted = this._encryptRaw(parameters);
      const encodedCiphertext = Buffer.concat([parameters.salt, encrypted]).toString(CIPHERTEXT_ENCODING);
      return Promise.resolve(encodedCiphertext);
    } catch(ex) {
      return Promise.reject(ex);
    }
  }

  _buildDecryptParameters(key, ciphertext) {
    const rawCiphertext = Buffer.from(ciphertext, CIPHERTEXT_ENCODING);
    const slicedRawData = this._sliceCiphertext(rawCiphertext);
    return this._createDecryptKeyObject(slicedRawData, key.key);
  }

  _decryptWithParameters(parameters){
    try {
      const decrypted = this._decryptRaw(parameters);
      return Promise.resolve(decrypted.toString(PLAINTEXT_ENCODING));
    } catch(ex) {
      return Promise.reject(ex);
    }
  }

  _encryptRaw(encryptionParameters) {
    const cipher = crypto.createCipheriv(ENCRYPTION_MODE, encryptionParameters.key, encryptionParameters.iv);
    const encrypted = cipher.update(encryptionParameters.rawPlaintext);
    return Buffer.concat([encryptionParameters.iv, encrypted, cipher.final(), cipher.getAuthTag()]);
  }

  _decryptRaw(decryptionParameters) {
    const decipher = crypto.createDecipheriv(ENCRYPTION_MODE, decryptionParameters.key, decryptionParameters.iv);
    decipher.setAuthTag(decryptionParameters.tag);

    const decrypted = decipher.update(decryptionParameters.encrypted);

    return Buffer.concat([decrypted, decipher.final()]);
  }

  _createEncryptKeyObject(plaintext, iv, keyAndSalt) {
    const salt = keyAndSalt.salt;
    const key = keyAndSalt.key;
    const rawPlaintext = Buffer.from(plaintext, PLAINTEXT_ENCODING);
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

    const ivEndIndex = this._passwordSaltSize + IV_SIZE_IN_BYTES;
    const authTagStartIndex = ciphertext.length - AUTH_TAG_LENGTH_IN_BYTES;

    return {
      passwordSalt: ciphertext.slice(0, this._passwordSaltSize),
      iv: ciphertext.slice(this._passwordSaltSize, ivEndIndex),
      encrypted: ciphertext.slice(ivEndIndex, authTagStartIndex),
      tag: ciphertext.slice(authTagStartIndex, ciphertext.length)
    };
  }

  _validateCiphertextMinLength(ciphertext) {
    const minimumCiphertextSize = this._passwordSaltSize + IV_SIZE_IN_BYTES + AUTH_TAG_LENGTH_IN_BYTES + 1;
    if (minimumCiphertextSize > ciphertext.length) {
      throw new Error('Ciphertext must be at least ' + minimumCiphertextSize + ' bytes long.');
    }
  }

  _validateNumber(parameter, name) {
    if (typeof parameter !== 'number') {
      throw new TypeError(name + ' must be a number.');
    }
  }

  _validateBuffer(parameter, name) {
    if (parameter instanceof Buffer === false) {
      throw new TypeError(name + ' must be a buffer.');
    }
  }

  _validateSaltSize(salt) {
    if(Buffer.from(salt, CIPHERTEXT_ENCODING).length !== this._passwordSaltSize) {
      throw new Error('Salt length must be ' + this._passwordSaltSize + '.');
    }
  }

  _validateKeyType(key) {
    if (key instanceof Key === false) {
      throw new TypeError('Key must be an Object returned by generateKey.');
    }
  }
}

module.exports = function(passwordSaltSize, iterationCount) {
  passwordSaltSize = passwordSaltSize || DEFAULT_PASSWORD_SALT_SIZE_IN_BYTES;
  iterationCount = iterationCount || DEFAULT_ITERATION_COUNT;

  return new Crypto(passwordSaltSize, iterationCount);
};
