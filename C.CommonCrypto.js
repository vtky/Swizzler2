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