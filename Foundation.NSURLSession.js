'use strict';

var proxyHost = '192.168.1.219';
var proxyPort = 8080;


/*
	Creating a Session
	+ sessionWithConfiguration:
		Creates a session with the specified session configuration.
	+ sessionWithConfiguration:delegate:delegateQueue:
		Creates a session with the specified session configuration, delegate, and operation queue.
*/

var NSMutableDictionary = ObjC.classes.NSMutableDictionary;


Interceptor.attach(ObjC.classes.NSURLSession['+ sessionWithConfiguration:'].implementation, {
    onEnter: function (args) {

    	console.log("Setting proxy for [NSURLSession sessionWithConfiguration:]");

        var configuration = ObjC.Object(args[2]);

		var proxyDict = NSMutableDictionary.dictionary();
		proxyDict.setValue_forKey_(1,"HTTPEnable");
		proxyDict.setValue_forKey_(proxyHost,"HTTPProxy");
		proxyDict.setValue_forKey_(proxyPort,"HTTPPort");
		proxyDict.setValue_forKey_(1,"HTTPSEnable");
		proxyDict.setValue_forKey_(proxyHost,"HTTPSProxy");
		proxyDict.setValue_forKey_(proxyPort,"HTTPSPort");

		configuration.setConnectionProxyDictionary_(proxyDict);
    },
});



Interceptor.attach(ObjC.classes.NSURLSession['+ sessionWithConfiguration:delegate:delegateQueue:'].implementation, {
    onEnter: function (args) {

    	console.log("Setting proxy for [NSURLSession sessionWithConfiguration:delegate:delegateQueue:]");

        var configuration = ObjC.Object(args[2]);

		var proxyDict = NSMutableDictionary.dictionary();
		proxyDict.setValue_forKey_(1,"HTTPEnable");
		proxyDict.setValue_forKey_(proxyHost,"HTTPProxy");
		proxyDict.setValue_forKey_(proxyPort,"HTTPPort");
		proxyDict.setValue_forKey_(1,"HTTPSEnable");
		proxyDict.setValue_forKey_(proxyHost,"HTTPSProxy");
		proxyDict.setValue_forKey_(proxyPort,"HTTPSPort");

		configuration.setConnectionProxyDictionary_(proxyDict);
    },
});










