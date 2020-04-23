'use strict';

const expect = require('chai').expect;
const Key = require('./key');

describe('Key', function() {

  describe('#constructor', function() {

    it('should set the key', function() {
      const key = new Key('key', 'salt');

      expect(key.key).to.eql('key');
    });

    it('should set the salt', function() {
      const key = new Key('key', 'salt');

      expect(key.salt).to.eql('salt');
    });

  });

});
