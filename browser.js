var nacl_factory = require("js-nacl");
var nacl = nacl_factory.instantiate();
exports = module.exports = require('./cs3a.js');

// export the nacl->sodium wrapper
exports.sodium = function()
{
  var self = {};
     //From Buffer to ArrayBuffer:
  function toArrayBuffer(buffer) {
    var ab = new ArrayBuffer(buffer.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buffer.length; ++i) {
        view[i] = buffer[i];
    }
    return ab;
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
      return {key:toBuffer(keypair.publicKey), secret:toBuffer(keypair.secretKey)};
  };
  self.crypto_box_beforenm = function(publickey, secretkey){
      var precomputedsharedkey = nacl.crypto_box_precompute(toArrayBuffer(publickey), toArrayBuffer(secretkey) );
      return toBuffer(precomputedsharedkey.boxK);
  };
  self.crypto_secretbox_open = function(ciphertextBin, nonceBin, keyBin){
      return toBuffer(
          nacl.crypto_secretbox_open(
              toArrayBuffer(ciphertextBin),
              toArrayBuffer(nonceBin),
              toArrayBuffer(keyBin)
          )
      );
  }
  self.crypto_secretbox = function(msgBin, nonceBin, keyBin){
      return toBuffer(
          nacl.crypto_secretbox(
              toArrayBuffer(msgBin),
              toArrayBuffer(nonceBin),
              toArrayBuffer(keyBin)
          )
      );
  }
  self.crypto_onetimeauth = function(message, secretkey){
      return toBuffer(
          nacl.crypto_onetimeauth(
              toArrayBuffer(message),
              toArrayBuffer(secretkey)
          )
      );
  }
  return self;
}

// deploy wrapper for browser
exports.crypt(exports.sodium());
