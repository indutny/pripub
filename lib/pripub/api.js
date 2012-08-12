var pripub = require('../pripub'),
    fs = require('fs'),
    path = require('path');

var api = exports;

function PriPub(options) {
  this.options = options || {};
  this.pri = null;
  this.pub = null;

  this.binding = new pripub.binding.PriPub();
  this._init = 0;
};

api.create = function create(options) {
  return new PriPub(options);
};

PriPub.prototype.init = function init(callback) {
  if (this._init) return callback(new Error('Double initialization'));
  this._init = 1;

  var self = this;

  this.pri = this.options.pri ||
             fs.readFileSync(path.resolve(process.env.HOME, '.ssh/id_rsa'));

  this.binding.onpassword = function onpassword() {
    // Private key is secured with password
    var password = self.options.password;

    function finish(password) {
      self.binding.setKeyPassword(new Buffer(password || ''));
    }

    if (typeof password === 'function') {
      // Make call to userland
      password.call(self, finish);
    } else {
      finish(password);
    }
  };

  this.binding.onload = function onload(err) {
    if (err) return callback(err);

    // Private key is loaded - time to load public key!
    if (self.options.pub) {
      // Use public key from options
      self.pub = self.options.pub;
    } else {
      // Get public key from private
      self.pub = self.binding.getPublicKey();
    }
    self.binding.setPublicKey(self.pub);

    self._init = 2;
    callback(null, self);
  };

  // All callbacks are set - time to
  this.binding.setPrivateKey(this.pri);
};

PriPub.prototype.encrypt = function encrypt(data, encoding) {
  if (this._init !== 2) throw new Error('Instance isn\'t ready');
  if (!(data instanceof Buffer) || encoding) data = new Buffer(data, encoding);

  return this.binding.encrypt(data);
};

PriPub.prototype.decrypt = function decrypt(data, encoding) {
  if (this._init !== 2) throw new Error('Instance isn\'t ready');
  if (!(data instanceof Buffer) || encoding) data = new Buffer(data, encoding);

  return this.binding.decrypt(data);
};

PriPub.prototype.getPublicKey = function getPublicKey() {
  if (this._init !== 2) throw new Error('Instance isn\'t ready');
  return this.pub;
};
