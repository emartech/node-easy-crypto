'use strict';

const crypto = require('crypto');

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
    return this._buildEncryptParameters(password, plaintext)
      .then(parameters => this._encryptWithParameters(parameters));
  }

  decrypt(password, ciphertext) {
    return this._buildDecryptParameters(password, ciphertext)
      .then(parameters => this._decryptWithParameters(parameters));
  }

  _buildEncryptParameters(password, plaintext) {
    return this._getRandomParameters()
      .then(randomParameters => this._generateKeyFromPassword(password, randomParameters.passwordSalt).then(key => {
        const encryptObject = this._createEncryptKeyObject(plaintext, randomParameters, key);
        return Promise.resolve(encryptObject);
      }));
  }

  _encryptWithParameters(parameters) {
    try {
      const encrypted = this._encryptRaw(parameters);
      const encodedCiphertext = Buffer.concat([parameters.passwordSalt, encrypted]).toString(CIPHERTEXT_ENCODING);
      return Promise.resolve(encodedCiphertext);
    } catch(ex) {
      return Promise.reject(ex);
    }
  }

  _encryptRaw(encryptionParameters) {
    const cipher = crypto.createCipheriv(ENCRYPTION_MODE, encryptionParameters.key, encryptionParameters.iv);
    const encrypted = cipher.update(encryptionParameters.rawPlaintext);
    return Buffer.concat([encryptionParameters.iv, encrypted, cipher.final(), cipher.getAuthTag()]);
  }

  _buildDecryptParameters(password, ciphertext) {
    const rawCiphertext = new Buffer(ciphertext, CIPHERTEXT_ENCODING);
    const slicedRawData = this._sliceCiphertext(rawCiphertext);
    return this._generateKeyFromPassword(password, slicedRawData.passwordSalt)
      .then(key => this._createDecryptKeyObject(slicedRawData, key));
  }

  _decryptWithParameters(parameters){
    try {
      const decrypted = this._decryptRaw(parameters);
      return Promise.resolve(decrypted.toString(PLAINTEXT_ENCODING));
    } catch(ex) {
      return Promise.reject(ex);
    }
  }

  _decryptRaw(decryptionParameters) {
    const decipher = crypto.createDecipheriv(ENCRYPTION_MODE, decryptionParameters.key, decryptionParameters.iv);
    decipher.setAuthTag(decryptionParameters.tag);

    const decrypted = decipher.update(decryptionParameters.encrypted);

    return Buffer.concat([decrypted, decipher.final()]);
  }

  _getRandomParameters() {
    return this._getRandomBytes(IV_SIZE_IN_BYTES + this._passwordSaltSize)
      .then(randomBytes => this._splitRandomBytes(randomBytes));
  }

  _getRandomBytes(length) {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(length, (err, bytes) => {
        if (err) return reject(err);
        return resolve(bytes);
      });
    });
  }

  _splitRandomBytes(randomBytes) {
    const passwordSalt = randomBytes.slice(0, this._passwordSaltSize);
    const iv = randomBytes.slice(this._passwordSaltSize, this._passwordSaltSize + IV_SIZE_IN_BYTES);
    return Promise.resolve({passwordSalt, iv});
  }

  _generateKeyFromPassword(password, passwordSalt) {
    const keyFromPassword = (resolve, reject) => crypto.pbkdf2(
      password,
      passwordSalt,
      this._iterationCount,
      KEY_SIZE_IN_BYTES,
      HMAC_MODE,
      (err, key) => {
        if (err) return reject(err);
        return resolve(key);
      }
    );
    return new Promise(keyFromPassword);
  }

  _createEncryptKeyObject(plaintext, randomParameters, key) {
    const iv = randomParameters.iv;
    const passwordSalt = randomParameters.passwordSalt;
    const rawPlaintext = new Buffer(plaintext, PLAINTEXT_ENCODING);
    return { iv, passwordSalt, rawPlaintext, key };
  }

  _createDecryptKeyObject(slicedRawData, key){
    const iv = slicedRawData.iv;
    const encrypted = slicedRawData.encrypted;
    const tag = slicedRawData.tag;
    const keyObject = { iv, encrypted, tag, key };
    return Promise.resolve(keyObject)
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

}

module.exports = function(passwordSaltSize, iterationCount) {
  passwordSaltSize = passwordSaltSize || DEFAULT_PASSWORD_SALT_SIZE_IN_BYTES;
  iterationCount = iterationCount || DEFAULT_ITERATION_COUNT;

  return new Crypto(passwordSaltSize, iterationCount);
};
module.exports.Crypto = Crypto;
