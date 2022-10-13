'use strict';

const NodeCache = require('node-cache');
const config = require('./config');

class CachedKeyring {

  get password() {
    return this._keyring.password;
  }

  get passwordSaltSize() {
    return this._keyring.passwordSaltSize;
  }

  get iterationCount() {
    return this._keyring.iterationCount;
  }

  constructor(keyring, encryptTtl, decryptPoolSize) {
    this._validateNumber(encryptTtl, 'encryptTtl');
    this._validateNumber(decryptPoolSize, 'decryptPoolSize');

    this._keyring = keyring;
    this._encryptTtl = encryptTtl;
    this._decryptPoolSize = decryptPoolSize;
    this._cache = new NodeCache();
  }

  getKey() {
    const key = this._cache.get(this._keyring.password);
    if (!key) {
      return this._keyring.getKey().then(key => {
        this._cache.set(this._keyring.password, key, this._encryptTtl);
        return Promise.resolve(key);
      });
    }
    return Promise.resolve(key);
  }

  getKeyForCiphertext(ciphertext) {
    const salt = this._keyring.getSaltFromCiphertext(ciphertext);

    const cacheKey = salt.toString(config.CIPHERTEXT_ENCODING) + this._keyring.password;
    const keyData = this._cache.get(cacheKey);

    if (!keyData) {
      this._cleanUpCache();

      return this._keyring.getKeyForCiphertext(ciphertext).then(key => {
        this._cache.set(cacheKey, {value: key, lastAccessed: Date.now()});

        return Promise.resolve(key);
      });
    } else {
      keyData.lastAccessed = Date.now();
      this._cache.set(cacheKey, keyData);

      return Promise.resolve(keyData.value);
    }
  }

  _cleanUpCache() {
    if (this._cache.getStats().keys < this._decryptPoolSize) {
      return;
    }

    this._cache.del(this._getOldestKey());
  }

  _getOldestKey() {
    let oldest;
    let oldestKey;
    for (const key of this._cache.keys()) {
      let current = this._cache.get(key);
      if (!current.hasOwnProperty('lastAccessed')) {
        continue;
      }
      if (!oldest || current.lastAccessed < oldest.lastAccessed) {
        oldest = current;
        oldestKey = key;
      }
    }
    return oldestKey;
  }

  _validateNumber(parameter, name) {
    if (typeof parameter !== 'number' || parameter !== parseInt(parameter, 10)) {
      throw new TypeError(name + ' must be a number.');
    }
  }

}

module.exports = CachedKeyring;
