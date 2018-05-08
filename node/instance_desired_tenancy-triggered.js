//
// This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// Ensure EC2 Instances have desired tenancy
// Description: Checks that EC2 Instances have desired tenancy
//
// Trigger Type: Change Triggered
// Scope of Changes: EC2:Instance
// Required Parameter: DesiredTenancy
// Example Value: dedicated

var aws = require('aws-sdk');
var config = new aws.ConfigService();
// This is where it's determined whether the resource is compliant or not.
// In this example, we look at the tenancy of the EC2 instance and determine whether it matches 
// the "DesiredTenancy" parameter that is passed to the rule. If the tenancy is not of the DesiredTenancy type, the 
// instance is marked non-compliant. Otherwise, it is marked complaint. 

function evaluateCompliance(configurationItem, ruleParameters, context) {
    checkDefined(configurationItem, "configurationItem");
    checkDefined(configurationItem.configuration, "configurationItem.configuration");
    checkDefined(ruleParameters, "ruleParameters");
    if ('AWS::EC2::Instance' !== configurationItem.resourceType) {
        return 'NOT_APPLICABLE';
    } if (ruleParameters.DesiredTenancy === configurationItem.configuration.placement.tenancy) {
        return 'COMPLIANT';
    } else {
        return 'NON_COMPLIANT';
    }
}
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
// Most of this code is boilerplate; use as is
exports.handler = function(event, context) {
    event = checkDefined(event, "event");
    var invokingEvent = JSON.parse(event.invokingEvent);
    var ruleParameters = JSON.parse(event.ruleParameters);
    var configurationItem = checkDefined(invokingEvent.configurationItem, "invokingEvent.configurationItem");
    var compliance = 'NOT_APPLICABLE';
    var putEvaluationsRequest = {};
    if (isApplicable(invokingEvent.configurationItem, event)) {
        // Invoke the compliance checking function.
        compliance = evaluateCompliance(invokingEvent.configurationItem, ruleParameters, context);
    }
    // Put together the request that reports the evaluation status
    // Note that we're choosing to report this evaluation against the resource that was passed in.
    // You can choose to report this against any other resource type, as long as it is supported by Config rules
   
    putEvaluationsRequest.Evaluations = [
        {
            ComplianceResourceType: configurationItem.resourceType,
            ComplianceResourceId: configurationItem.resourceId,
            ComplianceType: compliance,
            OrderingTimestamp: configurationItem.configurationItemCaptureTime
        }
    ];
    putEvaluationsRequest.ResultToken = event.resultToken;
    // Invoke the Config API to report the result of the evaluation
    config.putEvaluations(putEvaluationsRequest, function (err, data) {
        if (err) {
            context.fail(err);
        } else {
            context.succeed(data);
        }
    });
};
