'use strict';


function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
};


var CCOperation = {
    0: "kCCEncrypt",
    1: "kCCDecrypt"
};

var CCAlgorithm = {
    0: { name: "kCCAlgorithmAES128", blocksize: 16 },
    1: { name: "kCCAlgorithmDES", blocksize: 8 },
    2: { name: "kCCAlgorithm3DES", blocksize: 8 },
    3: { name: "kCCAlgorithmCAST", blocksize: 8 },
    4: { name: "kCCAlgorithmRC4", blocksize: 8 },
    5: { name: "kCCAlgorithmRC2", blocksize: 8 }
};







// CCCryptorStatus
// CCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
//     const void *key, size_t keyLength, const void *iv,
//     CCCryptorRef *cryptorRef);
Interceptor.attach(Module.findExportByName(null, "CCCryptorCreate"), {
	onEnter: function (args) {
        var op = args[0].toInt32();
        var alg = args[1].toInt32();
        var options = args[2].toInt32();
        var key = args[3];
        var keyLength = args[4].toInt32();
        var iv = args[5];

        var strKey = ba2hex(Memory.readByteArray(key, keyLength));

        if (iv == 0) {
            var strIV = "null";
        } else {
            var strIV = ba2hex(Memory.readByteArray(iv, CCAlgorithm[alg].blocksize));
        }
        
        console.log("CCCryptorCreate " + CCOperation[op] + " " + CCAlgorithm[alg].name + " key:" + strKey + " keyLength:" + keyLength*8 + " iv:" + strIV);
    }
});



// CCCryptorStatus
// CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options,
//     const void *key, size_t keyLength, const void *iv,
//     const void *dataIn, size_t dataInLength, void *dataOut,
//     size_t dataOutAvailable, size_t *dataOutMoved);
Interceptor.attach(Module.findExportByName(null, "CCCrypt"), {
	onEnter: function (args) {
        var op = args[0].toInt32();
        var alg = args[1].toInt32();
        var options = args[2].toInt32();
        var key = args[3];
        var keyLength = args[4].toInt32();
        var iv = args[5];
        var dataIn = args[6];
        var dataInLength = args[7].toInt32();
        var dataOut = args[8];
        var dataOutAvailable = args[9];

        var strKey = ba2hex(Memory.readByteArray(key, keyLength));

        if (iv == 0) {
            var strIV = "null";
        } else {
            var strIV = ba2hex(Memory.readByteArray(iv, CCAlgorithm[alg].blocksize));
        }

        var strDataIn = ba2hex(Memory.readByteArray(dataIn, dataInLength));

        console.log("CCCrypt " + CCOperation[op] + " " + CCAlgorithm[alg].name + " key:" + strKey + " keyLength:" + keyLength*8 + " iv:" + strIV + " dataIn:" + strDataIn);

    }
});









void replaced_CCHmac (CCHmacAlgorithm algorithm, const void *key, size_t keyLength, const void *data, size_t dataLength, void *macOut)
{
    NSString *nsstring_data = NSData2Hex([NSData dataWithBytes:data length:dataLength]);
    DDLogVerbose(@"CCHmac data: %@", nsstring_data);
    DDLogVerbose(@"CCHmac alg: %s, key: %@, keyLength: %lu bits", getHMACAlgorithmName(algorithm), NSData2Hex([NSData dataWithBytes:key length:keyLength]), keyLength*8);
    orig_CCHmac(algorithm, key, keyLength, data, dataLength, macOut);
}
/*
 Common HMAC Algorithm Interfaces
 This interface provides access to a number of HMAC algorithms. The following algorithms are available:

     kCCHmacAlgSHA1    - HMAC with SHA1 digest

     kCCHmacAlgMD5     - HMAC with MD5 digest

     kCCHmacAlgSHA256  - HMAC with SHA256 digest

     kCCHmacAlgSHA384  - HMAC with SHA384 digest

     kCCHmacAlgSHA224  - HMAC with SHA224 digest

     kCCHmacAlgSHA512  - HMAC with SHA512 digest

 The object declared in this interface, CCHmacContext, provides a handle
 for use with the CCHmacInit() CCHmacUpdate() and CCHmacFinal() calls to
 complete the HMAC operation.  In addition there is a one shot function,
 CCHmac() that performs a complete HMAC on a single piece of data.

 void CCHmacInit(CCHmacContext *ctx, CCHmacAlgorithm algorithm, const void *key, size_t keyLength);
 void CCHmacUpdate(CCHmacContext *ctx, const void *data, size_t dataLength);
 void CCHmacFinal(CCHmacContext *ctx, void *macOut);
 void CCHmac(CCHmacAlgorithm algorithm, const void *key, size_t keyLength, const void *data, size_t dataLength, void *macOut);
*/

var CCHmacAlgorithm = {
    0: { name: "kCCHmacAlgSHA1"},
    1: { name: "kCCHmacAlgMD5"},
    2: { name: "kCCHmacAlgSHA256"},
    3: { name: "kCCHmacAlgSHA384"},
    4: { name: "kCCHmacAlgSHA512"},
    5: { name: "kCCHmacAlgSHA224"}
};


Interceptor.attach(Module.findExportByName(null, "CCHmac"), {
    onEnter: function (args) {
        var algorithm = args[0].toInt32();
        var key = args[1];
        var keyLength = args[2].toInt32();
        var data = args[3];
        var dataLength = args[4].toInt32();
        var macOut = args[5];

        var strKey = ba2hex(Memory.readByteArray(key, keyLength));

        var strData = ba2hex(Memory.readByteArray(data, dataLength));

        console.log("CCCrypt " + CCHmacAlgorithm[algorithm].name + " key:" + strKey + " keyLength:" + keyLength*8 + " data:" + strData);
    }
});


















