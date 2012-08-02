var pripub = require('../pripub'),
    fs = require('fs'),
    path = require('path'),
    util = require('util');

var api = exports;

function PriPub(options) {
  var self = this;

  this.options = options || {};

  this.pri = this.options.pri ||
             fs.readFileSync(path.resolve(process.env.HOME, '.ssh/id_rsa'));

  this.binding = new pripub.binding.PriPub();

  this.binding.onpassword = function() {
    return new Buffer(self.options.password || '');
  };

  this.binding.setPrivateKey(this.pri);

  if (this.options.pub) {
    // Use public key from options
    this.pub = this.options.pub;
  } else {
    // Get public key from private
    this.pub = this.binding.getPublicKey();
  }
  this.binding.setPublicKey(this.pub);
};
util.inherits(PriPub, pripub.binding.PriPub);

api.create = function create(options) {
  return new PriPub(options);
};

PriPub.prototype.encrypt = function encrypt(data, encoding) {
  if (!(data instanceof Buffer) || encoding) data = new Buffer(data, encoding);

  return this.binding.encrypt(data);
};

PriPub.prototype.decrypt = function decrypt(data, encoding) {
  if (!(data instanceof Buffer) || encoding) data = new Buffer(data, encoding);

  return this.binding.decrypt(data);
};

PriPub.prototype.getPublicKey = function getPublicKey() {
  return this.pub;
};
