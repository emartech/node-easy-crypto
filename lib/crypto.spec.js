'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');
const crypto = require('crypto');
const Crypto = require('./crypto');
const Key = require('./key');
const defaultInstance = Crypto();

describe('Crypto', function() {

  describe('examples', function() {

    const password = crypto.randomBytes(24).toString('hex');
    const randomData = [
      crypto.randomBytes(1024).toString('hex'),
      crypto.randomBytes(1024).toString('hex'),
      crypto.randomBytes(1024).toString('hex')
    ];

    it('simple usage', function* () {
      const encrypted = yield defaultInstance.encrypt(password, randomData[0]);
      const decrypted = yield defaultInstance.decrypt(password, encrypted);

      expect(randomData[0]).to.eql(decrypted);
    });

    it('advanced usage', function*() {
      const salt = yield defaultInstance.generateSalt();
      const key = yield defaultInstance.generateKey(password, salt);
      const encrypted = yield randomData.map(data => defaultInstance.encryptWithKey(key, data));

      const saltFromEncrypted = defaultInstance.getSaltFromEncrypted(encrypted[0]);
      const keyForDecryption = yield defaultInstance.generateKey(password, saltFromEncrypted);
      const decrypted = yield encrypted.map(data => defaultInstance.decryptWithKey(keyForDecryption, data));
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

  });

  describe('#encrypt', function() {

    beforeEach(function() {
      this.sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
      this.sandbox.restore();
      this.sandbox = undefined;
    });

    it('should correctly prefix ciphertext with password salt and iv', function* () {
      stubRandomBytes.call(this, ['AAAAAAAAAAAA', 'BBBBBBBBBBBB']);

      const encrypted = Buffer.from(yield defaultInstance.encrypt('pw', 'data'), 'base64');

      expect(encrypted.slice(0, 12).toString('utf-8')).to.eql('AAAAAAAAAAAA');
      expect(encrypted.slice(12, 24).toString('utf-8')).to.eql('BBBBBBBBBBBB');
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
        const password = crypto.randomBytes(24).toString('hex');
        const randomData = crypto.randomBytes(1024).toString('hex');
        const encrypted = yield defaultInstance.encrypt(password, randomData);
        const tamperedEncrypted = tamperWithCiphertext(encrypted, testCase.index);
        let expectedError;

        try {
          yield defaultInstance.decrypt(password, tamperedEncrypted);
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
        yield defaultInstance.decrypt('does not matter', shortData);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(Error);
      expect(expectedError.message).to.eql('Ciphertext must be at least 41 bytes long.');
    });

    it('should fail during decryption if password is wrong', function* () {
        const password = crypto.randomBytes(24).toString('hex');
        const randomData = crypto.randomBytes(1024).toString('hex');
        const encrypted = yield defaultInstance.encrypt(password, randomData);
        let expectedError;

        try {
          yield defaultInstance.decrypt(password + 'X', encrypted);
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

  describe('#getSaltFromEncrypted', function() {

    it('should return the salt from cipherText', function () {
      let expectedSalt = 'A'.repeat(12);
      const encrypted = Buffer.from(expectedSalt + '123456').toString('base64');
      const actualSalt = defaultInstance.getSaltFromEncrypted(encrypted);

      expect(actualSalt.toString('utf-8')).to.eql(expectedSalt);
    });

  });

  describe('#generateKey', function() {

    beforeEach(function() {
      this.sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
      this.sandbox.restore();
      this.sandbox = undefined;
    });

    it('should return a Promise', function* () {
      const salt = Buffer.from('A'.repeat(12));
      const key = defaultInstance.generateKey('123456', salt);
      expect(key).to.be.instanceOf(Promise);
    });

    it('should resolve to a Key', function* () {
      const salt = Buffer.from('A'.repeat(12));
      const key = yield defaultInstance.generateKey('123456', salt);
      expect(key).to.be.instanceOf(Key);
    });

    it('should throw an error if the salt is not buffer', function* () {
      let expectedError;
      try {
        defaultInstance.generateKey('123456', 'notBuffer');
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('Salt must be a buffer.');
    });

    it('should throw an error if the salt length is not correct', function* () {
      const salt = Buffer.from('A'.repeat(10));

      let expectedError;
      try {
        defaultInstance.generateKey('123456', salt);
      } catch (ex) {
        expectedError = ex;
      }

      expect(expectedError).to.be.instanceOf(Error);
      expect(expectedError.message).to.eql('Salt length must be 12.');
    });

    it('should call crypto primitive with correct params', function* () {
      const salt = Buffer.from('A'.repeat(12));
      const password = '123456';
      const pbkdf2Spy = this.sandbox.spy(crypto, 'pbkdf2');

      defaultInstance.generateKey(password, salt);

      expect(pbkdf2Spy.getCall(0).args[0]).to.eql(password);
      expect(pbkdf2Spy.getCall(0).args[1]).to.eql(salt);
    });

  });

  describe('#generateSalt', function() {

    beforeEach(function() {
      this.sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
      this.sandbox.restore();
      this.sandbox = undefined;
    });

    it('generate a random salt', function* () {
      stubRandomBytes.call(this, ['AAAAAAAAAAAA']);
      const salt = yield defaultInstance.generateSalt();

      expect(salt).to.eql(Buffer.from('AAAAAAAAAAAA', 'utf-8'));
    });

  });

  describe('#encryptWithKey', function() {

    beforeEach(function() {
      this.sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
      this.sandbox.restore();
      this.sandbox = undefined;
    });

    it('should throw error if the key is not instance of Key', function () {
      let expectedError;
      try {
        defaultInstance.encryptWithKey('123456', '123');
      } catch (ex) {
        expectedError = ex;
      }
      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('Key must be an Object returned by generateKey.');
    });

    it('should return a Promise', function*()
    {
      const key = new Key(crypto.randomBytes(32), crypto.randomBytes(12));
      const encrypted = defaultInstance.encryptWithKey(key, '123');

      expect(encrypted).to.be.instanceOf(Promise);
      yield encrypted;
    });

  });

  describe('#decryptWithKey', function() {

    beforeEach(function() {
      this.sandbox = sinon.sandbox.create();
    });

    afterEach(function() {
      this.sandbox.restore();
      this.sandbox = undefined;
    });

    it('should throw error if the key is not instance of Key', function () {
      let expectedError;
      try {
        defaultInstance.decryptWithKey('123456', '123');
      } catch (ex) {
        expectedError = ex;
      }
      expect(expectedError).to.be.instanceOf(TypeError);
      expect(expectedError.message).to.eql('Key must be an Object returned by generateKey.');
    });

    it('should return a Promise', function*() {
      const key = yield defaultInstance.generateKey('password', crypto.randomBytes(12));
      const ciphertext = yield defaultInstance.encryptWithKey(key, 'data');
      const plaintext = defaultInstance.decryptWithKey(key, ciphertext);

      expect(plaintext).to.be.instanceOf(Promise);
      yield plaintext;
    });

  });

  function stubRandomBytes(randomBytes) {
    let counter = 0;
    this.sandbox.stub(crypto, 'randomBytes').callsFake(function(length, cb) {
      expect(length).to.eql(12);
      const randomBuffer = Buffer.from(randomBytes[counter], 'utf-8');
      counter++;
      return cb(null, randomBuffer);
    });
    // this.sandbox.stub(crypto, 'randomBytes', function(length, cb) {
    //   expect(length).to.eql(12);
    //   const randomBuffer = Buffer.from(randomBytes[counter], 'utf-8');
    //   counter++;
    //   return cb(null, randomBuffer);
    // });
  }

});
