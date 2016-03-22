//
// This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Ensure CloudTrail is Enabled for All Regions
// Description: Checks that a CloudTrail exists that is set to multi-region
// 
// Trigger Type: Periodic
// Required Parameter: None

var aws  = require('aws-sdk');
var s3 = new aws.S3();
var zlib = require('zlib');
var config = new aws.ConfigService();
 
// This function checks whether CloudTrail is enabled with multi region trail in the home region. 
// Do not use this rule in other regions.
 
function evaluateCompliance(configurationItems, ruleParameters, context) {
    checkDefined(configurationItems, "configurationItems");
    checkDefined(ruleParameters, "ruleParameters");
    
    for (var i = 0; i < configurationItems.length; i++) {
	    
        var item = configurationItems[i];
	    
        if (item.resourceType === 'AWS::CloudTrail::Trail') {
            
            if (item.configuration.isMultiRegionTrail) { return 'COMPLIANT'; }
            
        }
	
    }
    
    return 'NON_COMPLIANT';
    
}
 
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
 
// Reads and parses the ConfigurationSnapshot from the S3 bucket
// where Config is set up to deliver
 
function readSnapshot(s3client, s3key, s3bucket, callback) {
    var params = {
        Key: s3key,
        Bucket: s3bucket
    };
    var buffer = "";
    s3client.getObject(params)
        .createReadStream()
        .pipe(zlib.createGunzip())
        .on('data', function(chunk) {
            buffer = buffer + chunk;
        })
        .on('end', function() {
            callback(null, JSON.parse(buffer));
        })
        .on('error', function(err) {
            callback(err, null);
        });
}
 
// This is the handler that's invoked by Lambda
// Most of this code is boilerplate; use as is
 
exports.handler = function(event, context) {
    checkDefined(event, "event");
    var invokingEvent = JSON.parse(event.invokingEvent);
    var ruleParameters = JSON.parse(event.ruleParameters);
    var s3key = invokingEvent.s3ObjectKey;
    var s3bucket = invokingEvent.s3Bucket;
    var accountId = getAccountId(invokingEvent);
    var orderingTimestamp = invokingEvent.notificationCreationTime;
    readSnapshot(s3, s3key, s3bucket, function(err, snapshot) {
        var evaluation, putEvaluationsRequest;
        if (err === null) {
            evaluation = {
                ComplianceResourceType: 'AWS::::Account',
                ComplianceResourceId: accountId,
                ComplianceType: evaluateCompliance(snapshot.configurationItems, ruleParameters, context),
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
        } else {
            context.fail(err);
        }
    });
};
