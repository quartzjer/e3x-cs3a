var nacl_factory = require("js-nacl");
var nacl = nacl_factory.instantiate();
exports = module.exports = require('./cs3a.js');

// export the nacl->sodium wrapper
exports.sodium = function()
{
  var self = {};
     //From Buffer to Uint8Array:
  function toArray(buffer) {
    var view = new Uint8Array(buffer.length);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return view;
  }
    //From ArrayBuffer to Buffer
   function toBuffer(ab) {
    var buffer = new Buffer(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        buffer[i] = view[i];
    }
    return buffer;
  }

  self.crypto_secretbox_BOXZEROBYTES = nacl.crypto_secretbox_BOXZEROBYTES;
  self.crypto_box_keypair = function(){
      var keypair = nacl.crypto_box_keypair();
      return {publicKey:toBuffer(keypair.boxPk), secretKey:toBuffer(keypair.boxSk)};
  };
  self.crypto_box_beforenm = function(publickey, secretkey){
      var precomputedsharedkey = nacl.crypto_box_precompute(toArray(publickey), toArray(secretkey) );
      return toBuffer(precomputedsharedkey.boxK);
  };
  self.crypto_secretbox_open = function(ciphertextBin, nonceBin, keyBin){
      return toBuffer(
          nacl.crypto_secretbox_open(
              toArray(ciphertextBin),
              toArray(nonceBin),
              toArray(keyBin)
          )
      );
  }
  self.crypto_secretbox = function(msgBin, nonceBin, keyBin){
      return toBuffer(
          nacl.crypto_secretbox(
              toArray(msgBin),
              toArray(nonceBin),
              toArray(keyBin)
          )
      );
  }
  self.crypto_onetimeauth = function(message, secretkey){
      return toBuffer(
          nacl.crypto_onetimeauth(
              toArray(message),
              toArray(secretkey)
          )
      );
  }
  return self;
}

// deploy wrapper for browser
exports.crypt(exports.sodium());
