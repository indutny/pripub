var assert = require('assert'),
    pripub = require('..');

describe('PriPub addon', function() {
  var p;
  beforeEach(function() {
    p = pripub.create({
      password: process.env.PRIPUB_PASS
    });
  });

  it('should load private/public key pairs', function() {
    var text = new Array(997).join('big text');

    assert.equal(p.decrypt(p.encrypt(new Buffer(text))).toString(), text);
  });
});
