'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');
const Key = require('./key');
const Keyring = require('./keyring');
const CachedKeyring = require('./cachedkeyring');
const NodeCache = require('node-cache');

describe('CachedKeyring', function() {

  let key;
  let innerKeyring;
  let sandbox;

  beforeEach(function() {
    sandbox = sinon.createSandbox();
    key = new Key(
      Buffer.from('8fe0a1acb9a169cd01becb79fb588fc1e48e78fc7b7239507011036ac4594b56', 'hex'),
      Buffer.from('ec19c015cb492149890b66db', 'hex')
    );

    sandbox.stub(Keyring.prototype, 'getKey').resolves(key);
    sandbox.stub(Keyring.prototype, 'getKeyForCiphertext').resolves(key);

    innerKeyring = new Keyring('password', 12, 100);
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('#constructor', function() {

    [
      'not a number',
      1.1
    ].forEach(function(invalidInput) {
      it('should fail when created with invalid encrypt ttl (' + invalidInput + ')', function* () {
        let expectedError;

        try {
          new CachedKeyring(innerKeyring, invalidInput, 4);
        } catch (ex) {
          expectedError = ex;
        }

        expect(expectedError).to.be.instanceOf(TypeError);
        expect(expectedError.message).to.eql('encryptTtl must be a number.');
      });

      it('should fail when created with invalid decrypt pool size (' + invalidInput + ')', function* () {
        let expectedError;

        try {
          new CachedKeyring(innerKeyring, 2, invalidInput);
        } catch (ex) {
          expectedError = ex;
        }

        expect(expectedError).to.be.instanceOf(TypeError);
        expect(expectedError.message).to.eql('decryptPoolSize must be a number.');
      });
    });

    it('should expose keyring properties', function() {
      const keyring = new CachedKeyring(innerKeyring, 2, 4);

      expect(keyring.password).to.eql('password');
      expect(keyring.passwordSaltSize).to.eql(12);
      expect(keyring.iterationCount).to.eql(100);
    });

  });

  describe('#getKey', function() {

    it('returns the key from the original keyring', function*() {
      const keyring = new CachedKeyring(innerKeyring, 2, 4);
      const result = yield keyring.getKey();

      expect(Keyring.prototype.getKey.calledOnce).to.be.ok;
      expect(result).to.be.eql(key);
    });

    it('caches the result from the original keyring', function*() {
      const setSpy = sandbox.spy(NodeCache.prototype, 'set');

      const keyring = new CachedKeyring(innerKeyring, 2, 4);
      yield keyring.getKey();

      expect(setSpy.calledWith('password', key, 2)).to.be.ok;
    });

    it('returns the key from the cache the second time', function*() {
      const keyring = new CachedKeyring(innerKeyring, 2, 4);

      const result1 = yield keyring.getKey();
      const result2 = yield keyring.getKey();

      expect(Keyring.prototype.getKey.calledOnce).to.be.ok;
      expect(result1).to.be.eql(key);
      expect(result2).to.be.eql(key);
    });

  });

  describe('#getKeyForCiphertext', function() {

    const ciphertext = 'AAAAAAAAAAAAAAAAR/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=';
    const salt = Buffer.from('000000000000000000000000', 'hex');

    it('returns the key from the original keyring', function*() {
      const keyring = new CachedKeyring(innerKeyring, 2, 4);
      const result = yield keyring.getKeyForCiphertext(ciphertext);

      expect(Keyring.prototype.getKeyForCiphertext.calledOnce).to.be.ok;
      expect(result).to.be.eql(key);
    });

    it('caches the result from the original keyring', function*() {
      sandbox.stub(Date, 'now').returns(12345678);
      const setSpy = sandbox.spy(NodeCache.prototype, 'set');

      const keyring = new CachedKeyring(innerKeyring, 2, 4);
      yield keyring.getKeyForCiphertext(ciphertext);

      expect(setSpy.calledWith(salt.toString('base64') + 'password', {value: key, lastAccessed: 12345678})).to.be.ok;
    });

    it('returns the key from the cache the second time', function*() {
      const keyring = new CachedKeyring(innerKeyring, 2, 4);

      const result1 = yield keyring.getKeyForCiphertext(ciphertext);
      const result2 = yield keyring.getKeyForCiphertext(ciphertext);

      expect(Keyring.prototype.getKeyForCiphertext.calledOnce).to.be.ok;
      expect(result1).to.be.eql(key);
      expect(result2).to.be.eql(key);
    });

    it('updates the last access time in the cache for cached keys', function*() {
      let counter = 0;
      sandbox.stub(Date, 'now').callsFake(() => {
        ++counter;
        return counter;
      });
      const setSpy = sandbox.spy(NodeCache.prototype, 'set');

      const keyring = new CachedKeyring(innerKeyring, 2, 4);
      yield keyring.getKeyForCiphertext(ciphertext);
      yield keyring.getKeyForCiphertext(ciphertext);

      expect(setSpy.firstCall.calledWith(salt.toString('base64') + 'password', {value: key, lastAccessed: 1})).to.be.ok;
      expect(setSpy.secondCall.calledWith(salt.toString('base64') + 'password', {value: key, lastAccessed: 3})).to.be.ok;
    });

    it('removes old entries from the cache if necessary', function*() {
      let counter = 0;
      sandbox.stub(Date, 'now').callsFake(() => {
        ++counter;
        return counter;
      });
      const delSpy = sandbox.spy(NodeCache.prototype, 'del');

      const keyring = new CachedKeyring(innerKeyring, 2, 2);
      yield keyring.getKeyForCiphertext(ciphertext);
      yield keyring.getKeyForCiphertext('BAAAAAAAAAAAAAAAR/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=');
      yield keyring.getKeyForCiphertext('CAAAAAAAAAAAAAAAR/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=');

      expect(delSpy.calledWith(salt.toString('base64') + 'password')).to.be.ok;
    });

  });

});
