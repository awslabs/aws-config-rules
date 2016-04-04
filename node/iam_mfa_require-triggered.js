//
// This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Ensure IAM User has MFA Enabled
// Description: Checks that all IAM Users have MFA Enabled
// 
// Trigger Type: Change Triggered
// Scope of Changes: IAM:User
// Required Parameter: None

var aws = require('aws-sdk');
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
 
// Check whether the the resource has been deleted. If it has, then the evaluation is unnecessary.
 
function isApplicable(configurationItem, event){
    checkDefined(configurationItem, "configurationItem");
    checkDefined(event, "event");
    var status = configurationItem.configurationItemStatus;
    var eventLeftScope = event.eventLeftScope;
    return ('OK' === status || 'ResourceDiscovered' === status) && false === eventLeftScope;
}
 
// This is the handler that's invoked by Lambda

exports.handler = function(event, context) {
    event = checkDefined(event, "event");
    var invokingEvent = JSON.parse(event.invokingEvent);
    var ruleParameters = JSON.parse(event.ruleParameters);
    var configurationItem = checkDefined(invokingEvent.configurationItem, "invokingEvent.configurationItem");
    var putEvaluationsRequest = {};
    
    // Only call out Async if a User
    if (configurationItem.resourceType === 'AWS::IAM::User') {
	   
        iam.listMFADevices({ UserName: configurationItem.resourceName }, function(mfaerr, mfadata) {

            var ret = 'NON_COMPLIANT';
            
    		if (!mfaerr) {
    			
    		    if (mfadata.MFADevices.length > 0) {
                
                    ret = 'COMPLIANT';
                
                }
    			
    		} else {
    
    		    console.log(mfaerr);
    
    		}
    		
    		putEvaluationsRequest.Evaluations = [{
    	        ComplianceResourceType: configurationItem.resourceType,
    			ComplianceResourceId: configurationItem.resourceId,
    			ComplianceType: ret,
    			OrderingTimestamp: configurationItem.configurationItemCaptureTime
    		}];
    		    
    	    putEvaluationsRequest.ResultToken = event.resultToken;
    		 
            // Invoke the Config API to report the result of the evaluation
            config.putEvaluations(putEvaluationsRequest, function (err, data) {
        			if (err) {
        			    context.fail(err);
        			} else {
        			    context.succeed(data);
        			}
            });

	    });
	   
    } else {
 
	    // Put together the request that reports the evaluation status
	    // Note that we're choosing to report this evaluation against the resource that was passed in.
	    // You can choose to report this against any other resource type, as long as it is supported by Config rules
	    putEvaluationsRequest.Evaluations = [ { ComplianceResourceType: configurationItem.resourceType, ComplianceResourceId: configurationItem.resourceId, ComplianceType: 'NOT_APPLICABLE', OrderingTimestamp: configurationItem.configurationItemCaptureTime } ];
	    putEvaluationsRequest.ResultToken = event.resultToken;
	 
	    // Invoke the Config API to report the result of the evaluation
	    config.putEvaluations(putEvaluationsRequest, function (err, data) { if (err) { context.fail(err); } else { context.succeed(data); } });
	    
    }
    
};
