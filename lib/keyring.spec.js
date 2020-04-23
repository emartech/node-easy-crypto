'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');
const crypto = require('crypto');
const Key = require('./key');
const Keyring = require('./keyring');

describe('Keyring', function() {
  let sandbox;

  beforeEach(function() {
    sandbox = sinon.createSandbox();
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('#constructor', function() {

    it('should fail when created with invalid password salt size', function* () {
      let expectedError;

      try {
        new Keyring('password', 'not a number', 100);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('passwordSaltSize must be a number.');
    });

    it('should fail when created with invalid iteration count', function* () {
      let expectedError;

      try {
        new Keyring('password', 1, 'not a valid number');
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('iterationCount must be a number.');
    });

    it('should set the properties', function() {
      const keyring = new Keyring('password', 1, 2);

      expect(keyring.password).to.eql('password');
      expect(keyring.passwordSaltSize).to.eql(1);
      expect(keyring.iterationCount).to.eql(2);
    });

  });

  describe('#getKey', function() {

    it('should return a proper key', function*() {
      const keyring = new Keyring('password', 12, 100);

      const key = yield keyring.getKey();

      expect(key).to.be.an.instanceof(Key);
      expect(key.salt.length).to.eql(12);
    });

    it('should generate a different salt every time', function*() {
      const keyring = new Keyring('password', 12, 100);

      const key1 = yield keyring.getKey();
      const key2 = yield keyring.getKey();

      expect(key1.salt).to.not.eql(key2.salt);
    });

    it('should generate the proper key for a known salt and password', function*() {
      sandbox.stub(crypto, 'randomBytes').callsFake(function(length, cb) {
        return cb(null, Buffer.from('000000000000000000000000', 'hex'));
      });

      const keyring = new Keyring('password', 12, 100);
      const key = yield keyring.getKey();

      expect(key.salt).to.eql(Buffer.from('000000000000000000000000', 'hex'));
      expect(key.key).to.eql(Buffer.from('08d1d5773ee6e6542cd6e1ac5ffb8c3ddbeae9050de80f470386f1f4b5e24f48', 'hex'));
    });

  });

  describe('#getKeyForCiphertext', function() {

    it('should generate the proper key for a known salt and password', function*() {
      const ciphertext = 'AAAAAAAAAAAAAAAAR/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=';

      const keyring = new Keyring('password', 12, 100);
      const key = yield keyring.getKeyForCiphertext(ciphertext);

      expect(key.salt).to.eql(Buffer.from('000000000000000000000000', 'hex'));
      expect(key.key).to.eql(Buffer.from('08d1d5773ee6e6542cd6e1ac5ffb8c3ddbeae9050de80f470386f1f4b5e24f48', 'hex'));
    });

  });

  describe('#getSaltFromCiphertext', function() {

    it('should get the salt from the ciphertext', function() {
      const ciphertext = 'IuXiWhFZjWew8XM7R/xNXEuN8nyoB3sVrjbj1pMokFQe1Q0l32RpwbFuemPcllaRmOr8UZcaMHs=';

      const keyring = new Keyring('password', 12, 100);
      const salt = keyring.getSaltFromCiphertext(ciphertext);

      expect(salt).to.eql(Buffer.from('22e5e25a11598d67b0f1733b', 'hex'));
    });

  });

});
