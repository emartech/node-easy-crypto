'use strict';

const expect = require('chai').expect;
const easyCrypto = require('.');

describe('examples', function() {

  it('can encrypt and decrypt', function*() {
    const ecrypto = easyCrypto('password');

    const encrypted = yield ecrypto.encrypt('plain text');
    const decrypted = yield ecrypto.decrypt(encrypted);

    expect(decrypted).to.eql('plain text');
  });

  it('uses new key every time', function*() {
    const ecrypto = easyCrypto('password');

    const result1 = yield ecrypto.encrypt('plain text 1');
    const result2 = yield ecrypto.encrypt('plain text 2');

    expect(result1.slice(0, 16)).to.not.eql(result2.slice(0, 16));
  });

  it('can cache keys for a given time', function*() {
    const ecrypto = easyCrypto('password', { encryptCacheTtl: 10 });

    const result1 = yield ecrypto.encrypt('plain text 1');
    const result2 = yield ecrypto.encrypt('plain text 2');

    expect(result1.slice(0, 16)).to.eql(result2.slice(0, 16));
  });

  it('can cache a pool of decryption keys', function*() {
    const ecrypto = easyCrypto('password', { decryptCachePoolSize: 10 });

    const ciphertexts = [
      'AzLx2y8AOWEuMqTU523yqnDTKSsTCknLhrDeQ1vujLQgyfu/7XGuGw0TR+/prbKg3Og=',
      'AzLx2y8AOWEuMqTUyri06vwff7R2+GkrxXvRd/R59jibzWjAhxw3siixoXzhSHFRQkA=',
      'AzLx2y8AOWEuMqTULXmsHGGkJ8IZXInuVCNKOR0q3f/hWmZHB9QHYAmJcAPFa2Feeqs=',
    ];

    for (let ciphertext of ciphertexts) {
      expect(yield ecrypto.decrypt(ciphertext)).to.eql('plain text');
    }
  });

});
