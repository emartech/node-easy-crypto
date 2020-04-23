'use strict';

const crypto = require('crypto');
const config = require('./config');
const Key = require('./key');

class Keyring {
  _password;
  _passwordSaltSize;
  _iterationCount;

  get password() {
    return this._password;
  }

  get passwordSaltSize() {
    return this._passwordSaltSize;
  }

  get iterationCount() {
    return this._iterationCount;
  }

  constructor(password, passwordSaltSize, iterationCount) {
    this._validateNumber(passwordSaltSize, 'passwordSaltSize');
    this._validateNumber(iterationCount, 'iterationCount');

    this._password = password;
    this._passwordSaltSize = passwordSaltSize;
    this._iterationCount = iterationCount;
  }

  getKey() {
    return this._generateSalt().then(salt => this._generateKey(salt));
  }

  getKeyForCiphertext(ciphertext) {
    const salt = this.getSaltFromCiphertext(ciphertext);
    return this._generateKey(salt);
  }

  getSaltFromCiphertext(ciphertext) {
    return Buffer.from(ciphertext, config.CIPHERTEXT_ENCODING).slice(0, this._passwordSaltSize);
  }

  _generateKey(salt) {
    return new Promise((resolve, reject) => {
      return crypto.pbkdf2(
        this._password,
        salt,
        this._iterationCount,
        config.KEY_SIZE_IN_BYTES,
        config.HMAC_MODE,
        (err, key) => {
          if (err) return reject(err);
          return resolve(new Key(key, salt));
        }
      );
    });
  }

  _generateSalt() {
    return this._getRandomBytes(this._passwordSaltSize);
  }

  _getRandomBytes(length) {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(length, (err, bytes) => {
        if (err) return reject(err);
        return resolve(bytes);
      });
    });
  }

  _validateNumber(parameter, name) {
    if (typeof parameter !== 'number') {
      throw new TypeError(name + ' must be a number.');
    }
  }

}

module.exports = Keyring;
