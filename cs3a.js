var crypto = require('crypto');

exports.id = '3a';

// env-specific crypto methods
exports.crypt = function(ecc,aes)
{
  crypto.ecc = ecc;
  crypto.aes = aes;
}

exports.generate = function(cb)
{
  try {
    var k = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1);
  }catch(E){
    return cb(E);
  }
  cb(null, {key:k.PublicKey, secret:k.PrivateKey});
}

exports.Local = function(pair)
{
  var self = this;
  try{
    self.key = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, pair.key, true);
    self.secret = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, pair.secret);
    if(self.key.PublicKey.toString() != pair.key.toString()) throw new Error('invalid public key data');
    if(self.secret.PrivateKey.toString() != pair.secret.toString()) throw new Error('invalid secret key data');
  }catch(E){
    self.err = E;
  }

  // decrypt message body and return the inner
  self.decrypt = function(body){
    if(!Buffer.isBuffer(body)) return false;
    if(body.length < 21+4+4) return false;

    var keybuf = body.slice(0,21);
    var iv = body.slice(21,21+4);
    var innerc = body.slice(21+4,body.length-4);
    // mac is handled during verify stage

    try{
      var ephemeral = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, keybuf, true);
      var secret = self.secret.deriveSharedSecret(ephemeral);
    }catch(E){
      return false;
    }

    var key = fold(1,crypto.createHash("sha256").update(secret).digest());
    var ivz = new Buffer(12);
    ivz.fill(0);

    // aes-128 decipher the inner
    try{
      var inner = crypto.aes(false, key, Buffer.concat([iv,ivz]), innerc);
    }catch(E){
      return false;
    }
    
    return inner;
  };
}

exports.Remote = function(key)
{
  var self = this;
  try{
    self.endpoint = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, key, true);
    self.ephemeral = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1);
    self.token = crypto.createHash('sha256').update(self.ephemeral.PublicKey.slice(0,16)).digest().slice(0,16);
    self.seq = crypto.randomBytes(4).readUInt32LE(0); // start from random place
  }catch(E){
    self.err = E;
  }

  // verifies the hmac on an incoming message body
  self.verify = function(local, body){
    if(!Buffer.isBuffer(body)) return false;

    // derive shared secret from both identity keys
    var secret = local.secret.deriveSharedSecret(self.endpoint);

    // hmac key is the secret and seq bytes combined to make it unique each time
    var iv = body.slice(21,21+4);
    var mac = fold(3,crypto.createHmac("sha256", Buffer.concat([secret,iv])).update(body.slice(0,body.length-4)).digest());
    if(mac.toString('hex') != body.slice(body.length-4).toString('hex')) return false;
    
    return true;
  };

  self.encrypt = function(local, inner){
    if(!Buffer.isBuffer(inner)) return false;

    // get the shared secret to create the iv+key for the open aes
    try{
      var secret = self.ephemeral.deriveSharedSecret(self.endpoint);
    }catch(E){
      return false;
    }
    var key = fold(1,crypto.createHash("sha256").update(secret).digest());
    var iv = new Buffer(4);
    iv.writeUInt32LE(self.seq++,0);
    var ivz = new Buffer(12);
    ivz.fill(0);

    // encrypt the inner
    try{
      var innerc = crypto.aes(true, key, Buffer.concat([iv,ivz]), inner);
      var macsecret = local.secret.deriveSharedSecret(self.endpoint);
    }catch(E){
      return false;
    }

    // prepend the key and hmac it
    var macd = Buffer.concat([self.ephemeral.PublicKey,iv,innerc]);
    // key is the secret and seq bytes combined
    var hmac = fold(3,crypto.createHmac("sha256", Buffer.concat([macsecret,iv])).update(macd).digest());

    // create final message body
    return Buffer.concat([macd,hmac]);
  };

}

exports.Ephemeral = function(remote, body)
{
  var self = this;
  
  self.seq = crypto.randomBytes(4).readUInt32LE(0); // start from random place

  try{
    // sender token
    self.token = crypto.createHash('sha256').update(body.slice(0,16)).digest().slice(0,16);

    // extract received ephemeral key
    var key = new crypto.ecc.ECKey(crypto.ecc.ECCurves.secp160r1, body.slice(0,21), true);

    // get shared secret to make channel keys
    var secret = remote.ephemeral.deriveSharedSecret(key);
    self.encKey = fold(1,crypto.createHash("sha256")
      .update(secret)
      .update(remote.ephemeral.PublicKey)
      .update(key.PublicKey)
      .digest());
    self.decKey = fold(1,crypto.createHash("sha256")
      .update(secret)
      .update(key.PublicKey)
      .update(remote.ephemeral.PublicKey)
      .digest());
  }catch(E){
    self.err = E;
  }

  self.decrypt = function(outer){
    // extract the three buffers
    var seq = outer.slice(0,4);
    var cbody = outer.slice(4,outer.length-4);
    var mac1 = outer.slice(outer.length-4);

    // validate the hmac
    var key = Buffer.concat([self.decKey,seq]);
    var mac2 = fold(3,crypto.createHmac("sha256", key).update(cbody).digest());
    if(mac1.toString('hex') != mac2.toString('hex')) return false;

    // decrypt body
    var ivz = new Buffer(12);
    ivz.fill(0);
    try{
      var body = crypto.aes(false,self.decKey,Buffer.concat([seq,ivz]),cbody);
    }catch(E){
      return false;
    }
    return body;
  };

  self.encrypt = function(inner){
    // now encrypt the packet
    var iv = new Buffer(16);
    iv.fill(0);
    iv.writeUInt32LE(self.seq++,0);

    var cbody = crypto.aes(true, self.encKey, iv, inner);

    // create the hmac
    var key = Buffer.concat([self.encKey,iv.slice(0,4)]);
    var mac = fold(3,crypto.createHmac("sha256", key).update(cbody).digest());

    // return final body
    return Buffer.concat([iv.slice(0,4),cbody,mac]);
  };
}




var crypto = require("crypto");

var self;
exports.install = function(telehash)
{
  self = telehash;
  telehash.CSets["3a"] = exports;
}

var sodium;
exports.crypt = function(s)
{
  sodium = s;
}

exports.genkey = function(ret,cbDone,cbStep)
{
  var kp = sodium.crypto_box_keypair();
  ret["3a"] = kp.publicKey.toString("base64");
  ret["3a_secret"] = kp.secretKey.toString("base64");
  cbDone();
}

exports.loadkey = function(id, pub, priv)
{
  if(typeof pub == "string") pub = new Buffer(pub,"base64");
  if(!Buffer.isBuffer(pub) || pub.length != 32) return "invalid public key";
  id.key = pub;
  id.public = pub;

  if(priv)
  {
    if(typeof priv == "string") priv = new Buffer(priv,"base64");
    if(!Buffer.isBuffer(priv) || priv.length != 32) return "invalid private key";
    id.private = priv;
  }
  return false;
}

exports.openize = function(id, to, inner)
{
	if(!to.linekey) to.linekey = sodium.crypto_box_keypair();
  var linepub = to.linekey.publicKey;

  // get the shared secret to create the iv+key for the open aes
  var secret = sodium.crypto_box_beforenm(to.public, to.linekey.secretKey);
  var nonce = new Buffer("000000000000000000000000000000000000000000000001","hex");

  // encrypt the inner, encode if needed
  var body = (!Buffer.isBuffer(inner)) ? self.pencode(inner,id.cs["3a"].key) : inner;
  var cbody = sodium.crypto_secretbox(body, nonce, secret);
  cbody = cbody.slice(sodium.crypto_secretbox_BOXZEROBYTES); // remove zeros from nacl's api

  // prepend the line public key and hmac it  
  var secret = sodium.crypto_box_beforenm(to.public, id.cs["3a"].private);
  var macd = Buffer.concat([linepub,cbody]);
  var mac = sodium.crypto_onetimeauth(macd,secret);

  // create final body
  var body = Buffer.concat([mac,macd]);
  return self.pencode(0x3a, body);
}

exports.deopenize = function(id, open)
{
  var ret = {verify:false};
  if(!open.body) return ret;

  var mac1 = open.body.slice(0,16).toString("hex");
  ret.linepub = open.body.slice(16,48);
  var cbody = open.body.slice(48);

  var secret = sodium.crypto_box_beforenm(ret.linepub,id.cs["3a"].private);
  var nonce = new Buffer("000000000000000000000000000000000000000000000001","hex");

  // decipher the inner
  var zeros = new Buffer(Array(sodium.crypto_secretbox_BOXZEROBYTES)); // add zeros for nacl's api
  var body = sodium.crypto_secretbox_open(Buffer.concat([zeros,cbody]),nonce,secret);
  var inner = self.pdecode(body);
  if(!inner) return ret;
  ret.inner = inner;

  // if needs validation, load inner key info
  if(!open.from)
  {
    ret.key = inner.body;
    if(!ret.key || ret.key.length != 32) return ret;
    if(typeof inner.js.from != "object" || !inner.js.from["3a"]) return ret;
    if(crypto.createHash("SHA256").update(inner.body).digest("hex") != inner.js.from["3a"]) return ret;
  }else{
    ret.key = open.from.public;
  }

  // verify the hmac
  var secret = sodium.crypto_box_beforenm(ret.key, id.cs["3a"].private);
  var mac2 = sodium.crypto_onetimeauth(open.body.slice(16),secret).toString("hex");
  if(mac2 != mac1) return ret;

  // all good, cache+return
  ret.verify = true;
  ret.js = inner.js;
//    console.log("INNER",inner.js,ret.key.length);
  return ret;
}

// set up the line enc/dec keys
exports.openline = function(from, open)
{
  from.lineIV = 0;
  from.lineInB = new Buffer(from.lineIn, "hex");
  var secret = sodium.crypto_box_beforenm(open.linepub, from.linekey.secretKey);
  from.encKey = crypto.createHash("sha256")
    .update(secret)
    .update(new Buffer(from.lineOut, "hex"))
    .update(new Buffer(from.lineIn, "hex"))
    .digest();
  from.decKey = crypto.createHash("sha256")
    .update(secret)
    .update(new Buffer(from.lineIn, "hex"))
    .update(new Buffer(from.lineOut, "hex"))
    .digest();
  return true;
},

exports.lineize = function(to, packet)
{
	// now encrypt the packet
  var nonce = crypto.randomBytes(24);
  var cbody = sodium.crypto_secretbox(self.pencode(packet.js,packet.body), nonce, to.encKey);
  cbody = cbody.slice(sodium.crypto_secretbox_BOXZEROBYTES); // remove zeros from nacl's api

  // create final body
  var body = Buffer.concat([to.lineInB,nonce,cbody]);

  return self.pencode(null, body);
},

exports.delineize = function(from, packet)
{
  if(!packet.body) return "no body";
  // remove lineid
  packet.body = packet.body.slice(16);
  
  // decrypt body
  var nonce = packet.body.slice(0,24);
  var cbody = packet.body.slice(24);
  var zeros = new Buffer(Array(sodium.crypto_secretbox_BOXZEROBYTES)); // add zeros for nacl's api
  var deciphered = self.pdecode(sodium.crypto_secretbox_open(Buffer.concat([zeros,cbody]),nonce,from.decKey));
	if(!deciphered) return "invalid decrypted packet";

  packet.js = deciphered.js;
  packet.body = deciphered.body;
  return false;
}

