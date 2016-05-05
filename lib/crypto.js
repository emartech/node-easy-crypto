'use strict';

let crypto = require('crypto');

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

  *encryptAsync(password, plaintext) {
    let parameters = yield this._buildEncryptParameters(password, plaintext);

    let encrypted = this._encryptRaw(parameters);

    return Buffer.concat([parameters.passwordSalt, encrypted]).toString(CIPHERTEXT_ENCODING);
  }

  *decryptAsync(password, ciphertext) {
    let parameters = yield this._buildDencryptParameters(password, ciphertext);

    let decrypted = this._decryptRaw(parameters);

    return decrypted.toString(PLAINTEXT_ENCODING);
  }

  _validateNumber(parameter, name) {
    if (typeof parameter !== 'number') {
      throw new TypeError(name + ' must be a number.');
    }
  }

  *_buildEncryptParameters(password, plaintext) {
    let randomParameters = yield this._getRandomParameters();
    let key = yield this._generateKeyFromPasswordAsync(password, randomParameters.passwordSalt);
    let rawPlaintext = new Buffer(plaintext, PLAINTEXT_ENCODING);

    return {
      passwordSalt: randomParameters.passwordSalt,
      iv: randomParameters.iv,
      key: key,
      rawPlaintext: rawPlaintext
    };
  }

  *_buildDencryptParameters(password, ciphertext) {
    let rawCiphertext = new Buffer(ciphertext, CIPHERTEXT_ENCODING);
    let slicedRawData = this._sliceCiphertext(rawCiphertext);
    let key = yield this._generateKeyFromPasswordAsync(password, slicedRawData.passwordSalt);

    return {
      iv: slicedRawData.iv,
      encrypted: slicedRawData.encrypted,
      tag: slicedRawData.tag,
      key: key
    };
  }

  _encryptRaw(encryptionParameters) {
    let cipher = crypto.createCipheriv(ENCRYPTION_MODE, encryptionParameters.key, encryptionParameters.iv);

    let encrypted = cipher.update(encryptionParameters.rawPlaintext);

    return Buffer.concat([encryptionParameters.iv, encrypted, cipher.final(), cipher.getAuthTag()]);
  }

  _decryptRaw(decryptionParameters) {
    let decipher = crypto.createDecipheriv(ENCRYPTION_MODE, decryptionParameters.key, decryptionParameters.iv);
    decipher.setAuthTag(decryptionParameters.tag);

    let decrypted = decipher.update(decryptionParameters.encrypted);

    return Buffer.concat([decrypted, decipher.final()]);
  }

  *_getRandomParameters() {
    let randomBytes = yield this._randomBytesAsync(IV_SIZE_IN_BYTES + this._passwordSaltSize);
    let passwordSalt = randomBytes.slice(0, this._passwordSaltSize);
    let iv = randomBytes.slice(this._passwordSaltSize, this._passwordSaltSize + IV_SIZE_IN_BYTES);

    return { passwordSalt: passwordSalt, iv: iv };
  }

  _sliceCiphertext(ciphertext) {
    let minimumCiphertextSize = this._passwordSaltSize + IV_SIZE_IN_BYTES + AUTH_TAG_LENGTH_IN_BYTES + 1;
    if (minimumCiphertextSize > ciphertext.length) {
      throw new Error('Ciphertext must be at least ' + minimumCiphertextSize + ' bytes long.');
    }

    let ivEndIndex = this._passwordSaltSize + IV_SIZE_IN_BYTES;
    let authTagStartIndex = ciphertext.length - AUTH_TAG_LENGTH_IN_BYTES;

    return {
      passwordSalt: ciphertext.slice(0, this._passwordSaltSize),
      iv: ciphertext.slice(this._passwordSaltSize, ivEndIndex),
      encrypted: ciphertext.slice(ivEndIndex, authTagStartIndex),
      tag: ciphertext.slice(authTagStartIndex, ciphertext.length)
    };
  }

  _randomBytesAsync(length) {
    return new Promise((resolve, reject) => {
      crypto.randomBytes(length, (err, bytes) => {
        if (err) return reject(err);

        return resolve(bytes);
      });
    });
  }

  _generateKeyFromPasswordAsync(password, passwordSalt) {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, passwordSalt, this._iterationCount, KEY_SIZE_IN_BYTES, HMAC_MODE, (err, key) => {
        if (err) return reject(err);

        return resolve(key);
      });
    });
  }

}

module.exports = function(passwordSaltSize, iterationCount) {
  passwordSaltSize = passwordSaltSize || DEFAULT_PASSWORD_SALT_SIZE_IN_BYTES;
  iterationCount = iterationCount || DEFAULT_ITERATION_COUNT;

  return new Crypto(passwordSaltSize, iterationCount);
};
module.exports.Crypto = Crypto;
