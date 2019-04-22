//
// This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
//
// RDS DB Instances are encrypted and if an optional KMS Key ARN parameter is provided, we check whether the DB Instances were encrypted using the specified key 
//
// Trigger Type: Change Triggered
// Scope of Changes: RDS:Instance
// Accepted Parameters: KMSKeyARN (optional)
// Example Values: 'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab'

'use strict';
let aws = require('aws-sdk');
let config = new aws.ConfigService();

// This is where it's determined whether the resource is compliant or not.
function evaluateCompliance(configurationItem, ruleParameters) {
    checkDefined(configurationItem, 'configurationItem');
    checkDefined(configurationItem.configuration, 'configurationItem.configuration');
    checkDefined(ruleParameters, 'ruleParameters');
    // If the resource is not a RDS DBInstance, then we deem this resource to be not applicable. (If the scope of the rule is specified to include only
    // RDS DB Instances, this rule is invoked only for DB Instances.)
    if ('AWS::RDS::DBInstance' !== configurationItem.resourceType) {
        return 'NOT_APPLICABLE';
    }
    
    if (configurationItem.configuration.storageEncrypted) 
    {
    	//If KMS Key is provided as a rule parameter, check if the dbinstance is using this key for encryption
    	if(ruleParameters.KMSKeyARN)
        {
            // Encrypted with correct key
            if(ruleParameters.KMSKeyARN === configurationItem.configuration.kmsKeyId){
                 return 'COMPLIANT';
            }
            // Encrypted but not with specified KMS key
            return 'NON_COMPLIANT';
        }
        // Encrypted, no specific key needed
        return 'COMPLIANT';
    }
    else {
        // Not encrypted
        return 'NON_COMPLIANT';
    }
}

// Helper function used to validate input

function checkDefined(reference, referenceName) {
    if (!reference) {
        console.log('Error: ${referenceName} is not defined');
        throw referenceName;
    }
    return reference;
}

// Check whether the the resource has been deleted. If it has, then the evaluation is unnecessary.

function isApplicable(configurationItem, event) {
    checkDefined(configurationItem, 'configurationItem');
    checkDefined(event, 'event');
    const status = configurationItem.configurationItemStatus;
    const eventLeftScope = event.eventLeftScope;
    return ('OK' === status || 'ResourceDiscovered' === status) && false === eventLeftScope;
}

// This is the handler that's invoked by Lambda
// Most of this code is boilerplate; use as is

exports.handler = (event, context, callback) => {
    event = checkDefined(event, 'event');
    console.log('Received event:' + JSON.stringify(event, null, 4));
    const invokingEvent = JSON.parse(event.invokingEvent);
    const ruleParameters =  "ruleParameters" in event ? JSON.parse(event.ruleParameters) : {};
    const configurationItem = checkDefined(invokingEvent.configurationItem, 'invokingEvent.configurationItem');
    let compliance = 'NOT_APPLICABLE';

    if (isApplicable(invokingEvent.configurationItem, event)) {
        // Invoke the compliance checking function.
        compliance = evaluateCompliance(invokingEvent.configurationItem, ruleParameters);
    }

    // Put together the request that reports the evaluation status
    // Note that we're choosing to report this evaluation against the resource that was passed in.
    // You can choose to report this against any other resource type

    const evaluation = {
        ComplianceResourceType: configurationItem.resourceType,
        ComplianceResourceId: configurationItem.resourceId,
        ComplianceType: compliance,
        OrderingTimestamp: configurationItem.configurationItemCaptureTime
    };
    const putEvaluationsRequest = {
        Evaluations : [ evaluation ],
        ResultToken : event.resultToken
    };

    // Invoke the Config API to report the result of the evaluation
    console.log('Put Evaluation:' + JSON.stringify(evaluation, null, 4));
    config.putEvaluations(putEvaluationsRequest, callback);
};
