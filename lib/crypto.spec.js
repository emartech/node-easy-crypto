'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');
const crypto = require('crypto');
const Crypto = require('./crypto');
const Key = require('./key');
const Keyring = require('./keyring');

describe('Crypto', function() {

  let key;
  let defaultInstance;
  let sandbox;

  beforeEach(function() {
    sandbox = sinon.createSandbox();
    key = new Key(
      Buffer.from('8fe0a1acb9a169cd01becb79fb588fc1e48e78fc7b7239507011036ac4594b56', 'hex'),
      Buffer.from('ec19c015cb492149890b66db', 'hex')
    );
    defaultInstance = new Crypto(new Keyring('pw', 12, 100));
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('#encrypt', function() {

    it('should correctly prefix ciphertext with password salt and iv', function* () {
      let counter = 0;
      sandbox.stub(crypto, 'randomBytes').callsFake(function(length, cb) {
        ++counter;
        return cb(null, Buffer.from('00000000000000000000000' + counter, 'hex'));
      });

      const encrypted = Buffer.from(yield defaultInstance.encrypt('data'), 'base64');

      expect(encrypted.slice(0, 12).toString('hex')).to.eql('000000000000000000000001');
      expect(encrypted.slice(12, 24).toString('hex')).to.eql('000000000000000000000002');
      expect(encrypted.length).to.eql(24 + 4 + 16);
    });

  });

  describe('#decrypt', function() {

    [
      { partName: 'salt', index: 3 },
      { partName: 'iv', index: 13 },
      { partName: 'data', index: 29 },
      { partName: 'auth tag', index: 1051 }
    ].forEach(function(testCase) {
      it('should fail during decryption if ' + testCase.partName + ' is tampered with', function* () {
        const randomData = crypto.randomBytes(1024).toString('hex');
        const encrypted = yield defaultInstance.encrypt(randomData);
        const tamperedEncrypted = tamperWithCiphertext(encrypted, testCase.index);
        let expectedError;

        try {
          yield defaultInstance.decrypt(tamperedEncrypted);
        } catch (ex) {
          expectedError = ex;
        }

        expect(expectedError).to.be.instanceOf(Error);
        expect(expectedError.message).to.eql('Unsupported state or unable to authenticate data');
      });
    });

    it('should fail during decryption if ciphertext is too short', function* () {
      const shortData = crypto.randomBytes(40).toString('base64');
      let expectedError;

      try {
        yield defaultInstance.decrypt(shortData);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(Error);
      expect(expectedError.message).to.eql('Ciphertext must be at least 41 bytes long.');
    });

    it('should fail during decryption if password is wrong', function* () {
      const randomData = crypto.randomBytes(1024).toString('hex');
      const encrypted = yield defaultInstance.encrypt(randomData);
      let expectedError;

      try {
        const otherInstance = new Crypto(new Keyring('pw2', 12, 100));
        yield otherInstance.decrypt(encrypted);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(Error);
      expect(expectedError.message).to.eql('Unsupported state or unable to authenticate data');
    });

    function tamperWithCiphertext(ciphertext, index) {
      const rawCiphertext = Buffer.from(ciphertext, 'base64');
      rawCiphertext[index] = rawCiphertext[index] === 0x01 ? 0x02 : 0x01;
      return rawCiphertext.toString('base64');
    }

  });

});
