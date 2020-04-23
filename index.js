'use strict';

const config = require('./lib/config');
const Crypto = require('./lib/crypto');
const Keyring = require('./lib/keyring');
const CachedKeyring = require('./lib/cachedkeyring');

module.exports = function(password, options) {
  options = Object.assign({
    encryptCacheTtl: 0,
    decryptCachePoolSize: 0,
  }, options || {});

  let keyring = new Keyring(password, config.PASSWORD_SALT_SIZE_IN_BYTES, config.ITERATION_COUNT);
  if (options.encryptCacheTtl || options.decryptCachePoolSize) {
    keyring = new CachedKeyring(keyring, options.encryptCacheTtl, options.decryptCachePoolSize);
  }

  return new Crypto(keyring);
};
