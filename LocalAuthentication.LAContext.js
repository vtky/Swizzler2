'use strict';

//- (void) evaluatePolicy:(LAPolicy)policy 
//         localizedReason:(NSString *)localizedReason 
//         reply:(void (^)(BOOL success, NSError *error))reply;


Interceptor.attach(ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
    onEnter: function(args) {
        var reply = new ObjC.Block(args[4]);
        const replyCallback = reply.implementation;
        reply.implementation = function (error, value)  {
            return replyCallback(1, null);
        };
    },
});