//
// This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Ensure IAM password policy requires a lowercase character.
// Description: Checks that the IAM password policy requires a lowercase character
// 
// Trigger Type: Periodic
// Required Parameter: None

var aws  = require('aws-sdk');
var s3 = new aws.S3();
var zlib = require('zlib');
var config = new aws.ConfigService();
var iam = new aws.IAM();

// Helper function used to validate input
function checkDefined(reference, referenceName) {
    if (!reference) {
        console.log("Error: " + referenceName + " is not defined");
        throw referenceName;
    }
    return reference;
}
 
// Extract the account ID from the event
function getAccountId(invokingEvent) {
    checkDefined(invokingEvent, "invokingEvent");
    checkDefined(invokingEvent.s3ObjectKey, "invokingEvent.s3ObjectKey");
    var accountIdPattern = /AWSLogs\/(\d+)\/Config/;
    return accountIdPattern.exec(invokingEvent.s3ObjectKey)[1];
}
 
// This is the handler that's invoked by Lambda
exports.handler = function(event, context) {
 
    checkDefined(event, "event");
    var invokingEvent = JSON.parse(event.invokingEvent);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    var accountId = getAccountId(invokingEvent);
    var orderingTimestamp = invokingEvent.notificationCreationTime;
    
    iam.getAccountPasswordPolicy(function(err, iamdata) {

        if (!err) {
    
            var compliance = 'NON_COMPLIANT';
            
            if (iamdata.PasswordPolicy.RequireLowercaseCharacters == 'true') { compliance = 'COMPLIANT'; }
            
            evaluation = {
                ComplianceResourceType: 'AWS::::Account',
                ComplianceResourceId: accountId,
                ComplianceType: compliance,
                OrderingTimestamp: orderingTimestamp
            };
    
            putEvaluationsRequest = {
               Evaluations: [
                   evaluation
               ],
               ResultToken: event.resultToken
            };
    
            config.putEvaluations(putEvaluationsRequest, function (err, data) {
                if (err) {
                    context.fail(err);
                } else {
                    context.succeed(data);
                }
            });
            
        }
            
    });
};
