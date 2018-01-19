'use strict';

class Key {
  constructor(key, salt) {
    this._key = key;
    this._salt = salt;
  }

  get key() {
    return this._key;
  }

  get salt() {
    return this._salt;
  }
}

module.exports = Key;