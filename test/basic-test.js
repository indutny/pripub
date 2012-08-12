var assert = require('assert'),
    prompt = require('prompt'),
    pripub = require('..');

prompt.start();

describe('PriPub addon', function() {
  var p;
  beforeEach(function(callback) {
    p = pripub.create({
      password: function(callback) {
        var property = {
          name: 'password',
          message: 'Your private key password',
          default: 'empty'
        };

        prompt.get(property, function(err, result) {
          if (err) return callback();
          callback(result.password);
        });
      }
    });
    p.init(callback);
  });

  it('should load private/public key pairs', function() {
    var text = new Array(997).join('big text');

    assert.equal(p.decrypt(p.encrypt(new Buffer(text))).toString(), text);
  });
});
