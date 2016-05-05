'use strict';

let expect = require('chai').expect;
let sinon = require('sinon');
let crypto = require('crypto');
let Crypto = require('./crypto');
let defaultInstance = Crypto();

describe('Crypto', function() {

  describe('sanity check', function() {

    it('should correctly decrypt encrypted data', function* () {
      let password = crypto.randomBytes(24).toString('hex');
      let randomData = crypto.randomBytes(1024).toString('hex');

      let encrypted = yield defaultInstance.encryptAsync(password, randomData);

      let decrypted = yield defaultInstance.decryptAsync(password, encrypted);

      expect(randomData).to.eql(decrypted);
    });

  });

  describe('#constructor', function() {

    it('should fail when created with invalid password salt size', function* () {
      let expectedError;

      try {
        Crypto('not a number', 10000);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('passwordSaltSize must be a number.');
    });

    it('should fail when created with invalid iteration count', function* () {
      let expectedError;

      try {
        Crypto(1, 'not a valid number');
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('iterationCount must be a number.');
    });

    it('should should initializes correctly with default configuration', function* () {
      let instance = Crypto();

      expect(instance).to.be.instanceOf(Crypto.Crypto);
      expect()
    });

  });

  describe('#encryptAsync', function() {

    beforeEach(function() {
      this.sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
      this.sandbox.restore();
      this.sandbox = undefined;
    });

    it('should correctly prefix ciphertext with password salt and iv', function* () {
      stubRandomBytes.call(this, 'AAAAAAAAAAAABBBBBBBBBBBB');

      let encrypted = new Buffer(yield defaultInstance.encryptAsync('pw', 'data'), 'base64');

      expect(encrypted.slice(0, 12).toString('utf-8')).to.eql('AAAAAAAAAAAA');
      expect(encrypted.slice(12, 24).toString('utf-8')).to.eql('BBBBBBBBBBBB');
      expect(encrypted.length).to.eql(24 + 4 + 16);
    });

    function stubRandomBytes(string) {
      this.sandbox.stub(crypto, 'randomBytes', function(length, cb) {
        expect(length).to.eql(24);
        return cb(null, new Buffer(string, 'utf-8'));
      });
    }

  });

  describe('#decryptAsync', function() {

    [
      { partName: 'salt', index: 3 },
      { partName: 'iv', index: 13 },
      { partName: 'data', index: 29 },
      { partName: 'auth tag', index: 1051 }
    ].forEach(function(testCase) {
      it('should fail during decryption if ' + testCase.partName + ' is tampered with', function* () {
        let password = crypto.randomBytes(24).toString('hex');
        let randomData = crypto.randomBytes(1024).toString('hex');
        let encrypted = yield defaultInstance.encryptAsync(password, randomData);
        let tamperedEncrypted = tamperWithCiphertext(encrypted, testCase.index);
        let expectedError;

        try {
          yield defaultInstance.decryptAsync(password, tamperedEncrypted);
        } catch (ex) {
          expectedError = ex;
        }

        expect(expectedError).to.be.instanceOf(Error);
        expect(expectedError.message).to.eql('Unsupported state or unable to authenticate data');
      });
    });

    it('should fail during decryption if ciphertext is too short', function* () {
      let shortData = crypto.randomBytes(40).toString('base64');
      let expectedError;

      try {
        yield defaultInstance.decryptAsync('does not matter', shortData);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(Error);
      expect(expectedError.message).to.eql('Ciphertext must be at least 41 bytes long.');
    });

    it('should fail during decryption if password is wrong', function* () {
        let password = crypto.randomBytes(24).toString('hex');
        let randomData = crypto.randomBytes(1024).toString('hex');
        let encrypted = yield defaultInstance.encryptAsync(password, randomData);
        let expectedError;

        try {
          yield defaultInstance.decryptAsync(password + 'X', encrypted);
        } catch (ex) {
          expectedError = ex;
        }

        expect(expectedError).to.be.instanceOf(Error);
        expect(expectedError.message).to.eql('Unsupported state or unable to authenticate data');
    });

    function tamperWithCiphertext(ciphertext, index) {
      let rawCiphertext = new Buffer(ciphertext, 'base64');
      rawCiphertext[index] = rawCiphertext[index] === 0x01 ? 0x02 : 0x01;
      return rawCiphertext.toString('base64');
    }

  });

});
