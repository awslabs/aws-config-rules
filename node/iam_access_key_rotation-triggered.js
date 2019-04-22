//
// This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Ensure IAM User Access Key Rotation
// Description: Checks that the IAM User's Access Keys have been rotated within the specified number of days.
//
// Trigger Type: Change Triggered
// Scope of Changes: IAM:User
// Required Parameter: MaximumAccessKeyAge
// Example Value: 90

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
function isApplicable(configurationItem, event) {
	
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
	var compliance = 'NOT_APPLICABLE';
	var putEvaluationsRequest = {};
    
	// Only run check on IAM Users
	if (configurationItem.resourceType === 'AWS::IAM::User') {
	   
		// List all Access Keys for user
		iam.listAccessKeys({ UserName: configurationItem.resourceName }, function(keyerr, keydata) {

			var ret = 'NOT_APPLICABLE';

			if (!keyerr) {
				
				// Only check dates on users with keys
				if (keydata.AccessKeyMetadata.length > 0) {

					// Check all keys
					for (var k = 0; k < keydata.AccessKeyMetadata.length; k++) {

						var now = Date.now();

						if (Math.floor((now - Date.parse(keydata.AccessKeyMetadata[k].CreateDate)) / 86400000) > ruleParameters.MaximumAccessKeyAge) {

							ret = 'NON_COMPLIANT';

						} else {
							
							ret = 'COMPLIANT';
							
						}
							
					}
				}
				
			} else {

				console.log(keyerr);

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
 
		// NOT APPLICABLE
		putEvaluationsRequest.Evaluations = [ { ComplianceResourceType: configurationItem.resourceType, ComplianceResourceId: configurationItem.resourceId, ComplianceType: compliance, OrderingTimestamp: configurationItem.configurationItemCaptureTime } ];
		putEvaluationsRequest.ResultToken = event.resultToken;
		config.putEvaluations(putEvaluationsRequest, function (err, data) { if (err) { context.fail(err); } else { context.succeed(data); } });

	}
    
};
