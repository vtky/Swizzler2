'use strict';
// Creating an NSURL Object

//    + URLWithString:
//    - initWithString:
//    + URLWithString:relativeToURL:
//    - initWithString:relativeToURL:
//    + fileURLWithPath:isDirectory:
//    - initFileURLWithPath:isDirectory:
//    + fileURLWithPath:
//    - initFileURLWithPath:
//    + fileURLWithPathComponents:
//    + URLByResolvingAliasFileAtURL:options:error:
//    + URLByResolvingBookmarkData:options:relativeToURL:bookmarkDataIsStale:error:
//    - initByResolvingBookmarkData:options:relativeToURL:bookmarkDataIsStale:error:
//    + fileURLWithFileSystemRepresentation:isDirectory:relativeToURL:
//    - getFileSystemRepresentation:maxLength:
//    - initFileURLWithFileSystemRepresentation:isDirectory:relativeToURL:


// + (id)URLWithString:(NSString *)URLString
Interceptor.attach(ObjC.classes.NSURL['+ URLWithString:'].implementation, {
    onEnter: function (args) {
        var url = ObjC.Object(args[2]).toString();
        console.log("NSURL URLWithString: " + url);
    },
});

// - (instancetype)initWithString:(NSString *)URLString
Interceptor.attach(ObjC.classes.NSURL['- initWithString:'].implementation, {
    onEnter: function (args) {
        var url = ObjC.Object(args[2]).toString();
        console.log("NSURL initWithString: " + url);
    },
});