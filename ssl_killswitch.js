/*
	Thanks to Alban Diquet for his SSL Kill Switch 2 project - https://github.com/nabla-c0d3/ssl-kill-switch2
*/

'use strict';


/*
	Stuff from nabla-c0d3's SSL Kill Switch 2 (https://github.com/nabla-c0d3/ssl-kill-switch2) converted to run with Frida.

	No idea currently why all of this does not work with iOS 10.
*/
var errSSLServerAuthCompleted = -9481; /* <Security/SecureTransport.h> peer cert is valid, or was ignored if verification disabled */
var kSSLSessionOptionBreakOnServerAuth = 0;
var noErr = 0;

/* OSStatus SSLHandshake ( SSLContextRef context ); */
var SSLHandshake = new NativeFunction(
	Module.findExportByName("Security", "SSLHandshake"),
	'int',
	['pointer']
);

Interceptor.replace(SSLHandshake, new NativeCallback(function (context) {
	var result = SSLHandshake(context);

	// Hijack the flow when breaking on server authentication
	if (result == errSSLServerAuthCompleted) {
		console.log("Relacing SSLHandshake");
		// Do not check the cert and call SSLHandshake() again
		return SSLHandshake(context);
	}

	return result;
}, 'int', ['pointer']));


/* SSLContextRef SSLCreateContext ( CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType ); */
var SSLCreateContext = new NativeFunction(
	Module.findExportByName("Security", "SSLCreateContext"),
	'pointer',
	['pointer', 'int', 'int']
);

Interceptor.replace(SSLCreateContext, new NativeCallback(function (alloc, protocolSide, connectionType) {
	console.log("Relacing SSLCreateContext");
	var sslContext = SSLCreateContext(alloc, protocolSide, connectionType);

	// Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
	SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, 1);
	return sslContext;
}, 'pointer', ['pointer', 'int', 'int']));


/* OSStatus SSLSetSessionOption ( SSLContextRef context, SSLSessionOption option, Boolean value );*/
var SSLSetSessionOption = new NativeFunction(
	Module.findExportByName("Security", "SSLSetSessionOption"),
	'int',
	['pointer', 'int', 'bool']
);

Interceptor.replace(SSLSetSessionOption, new NativeCallback(function (context, option, value) {
	// Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
	if (option == kSSLSessionOptionBreakOnServerAuth) {
		console.log("Relacing SSLSetSessionOption");
		return noErr;
	}
	return SSLSetSessionOption(context, option, value);
}, 'int', ['pointer', 'int', 'bool']));




/*
	The old way of killing SSL Pinning
*/

// SecTrustResultType
var kSecTrustResultInvalid = 0;
var kSecTrustResultProceed = 1;
// var kSecTrustResultConfirm = 2 // Deprecated
var kSecTrustResultDeny = 3;
var kSecTrustResultUnspecified = 4;
var kSecTrustResultRecoverableTrustFailure = 6;
var kSecTrustResultFatalTrustFailure = 6;
var kSecTrustResultOtherError = 7;


/*
	OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);
*/
var SecTrustEvaluate = new NativeFunction(
	Module.findExportByName("Security", "SecTrustEvaluate"),
	'int',
	['pointer', 'pointer']
);

Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
	console.log("Relacing SecTrustEvaluate");
	var ret = SecTrustEvaluate(trust, result);
	result = kSecTrustResultProceed;
	return ret;
}, 'int', ['pointer', 'pointer']));




/*
	Killing SSL Pinning of some of the commonly encountered frameworks
*/

if (ObjC.classes.AFSecurityPolicy) {
	/* AFNetworking */
	Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
		onEnter: function (args) {
			console.log("Relacing AFSecurityPolicy setSSLPinningMode = 0 was " + args[2]);
			args[2] = ptr('0x0');
		}
	});

	Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
		onEnter: function (args) {
			console.log("Relacing AFSecurityPolicy setAllowInvalidCertificates = 1 was " + args[2]);
			args[2] = ptr('0x1');
		}
	});
}


if (ObjC.classes.KonyUtil) {
	/* Kony */
	Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowSelfSignedCertificate'].implementation, {
		onLeave: function (retval) {
			console.log("Relacing KonyUtil shouldAllowSelfSignedCertificate = 1 was " + retval);
			retval.replace(0x1);
		}
	});

	Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowBundledWithSystemDefault'].implementation, {
		onLeave: function (retval) {
			console.log("Relacing KonyUtil shouldAllowBundledWithSystemDefault = 1 was " + retval);
			retval.replace(0x1);
		}
	});


	Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowBundledOnly'].implementation, {
		onLeave: function (retval) {
			console.log("Relacing KonyUtil shouldAllowBundledOnly = 0 was " + retval);
			retval.replace(0x0);
		}
	});
}




/*
	Other uncommon crap that I come across
*/

if (ObjC.classes.VGuardManager) {
	/* vkey */
	Interceptor.attach(ObjC.classes.VGuardManager['- setEnableSSLPinning:'].implementation, {
		onEnter: function (args) {
			console.log("Relacing VGuardManager setEnableSSLPinning = 0 was " + args[2]);
			args[2] = ptr('0x0');
		}
	});
}


if (ObjC.classes.eAhJgIkSdNCToZQwjpbnNbjfvZlYUSbyIFtfxkXSgI) {
	Interceptor.attach(ObjC.classes.eAhJgIkSdNCToZQwjpbnNbjfvZlYUSbyIFtfxkXSgI['- setIsSSLHookDetected:'].implementation, {
		onEnter: function (args) {
			console.log("Relacing eAhJgIkSdNCToZQwjpbnNbjfvZlYUSbyIFtfxkXSgI setIsSSLHookDetected = 0 was " + args[2]);
			args[2] = ptr('0x0');
		}
	});
}





