/*
 This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)

 Rule Name:
    LAMBDA_ENVIRONMVARS_CHECK
 Description:
    Validate Lambda environment variables
 Trigger:
    Change Triggered
 Resource Type to report on:
    AWS::Lambda::Function
 Rule Parameters:
    | -------------- | -------------------- | --------- | --------------------------------------------- | ------------------|
    | Parameter Key  | Parameter Value      | Type      | Description                                   |     Notes         |
    | -------------- | -------------------- | --------- | --------------------------------------------- | ------------------|
    | Anything       | *                    | Optional  | Means this environment variable MUST exist    | having * as value |
    |                |                      |           | with the key "Anything", otherwise the        | means this envvar |
    |                |                      |           | function will be NON_COMPLIANT                | must exist        |
    | -------------- | -------------------- | --------- | --------------------------------------------- | ------------------|
    | Anything       | !                    | Optional  | Means this environment variable MUST NOT      | having ! as value |
    |                |                      |           | exist with the key "Anything", otherwise the  | means this envvar |
    |                |                      |           | function will be NON_COMPLIANT                | must not exist    |
    | -------------- | -------------------- | --------- | --------------------------------------------- | ------------------|
    | Anything       | !someValue           | Optional  | Means this environment variable MUST NOT have | if it exists with |
    |                |                      |           | the value "someValue", otherwise the          | other value this  |
    |                |                      |           | function will be NON_COMPLIANT                | will be ignored   |
    | -------------- | -------------------- | --------- | --------------------------------------------- | ------------------|
    | Anything       | someValue            | Optional  | Means this environment variable MUST exist    | case insensitive  |
    |                |                      |           | and have the value "someValue", otherwise the | for keys and      |
    |                |                      |           | function will be NON_COMPLIANT                | values            |
    | -------------- | -------------------- | --------- | --------------------------------------------- | ------------------|

 Example:
    | -------------- | -------------------- | ------------------------------------------------------------------------- |
    | Parameter Key  | Parameter Value      | Notes                                                                     |
    | -------------- | -------------------- | ------------------------------------------------------------------------- | 
    | appVersion     | *                    | Means that the updated lambda function MUST have an environment           |
    |                |                      | variable with the key "appVersion" or it will be considered NON_COMPLIANT |
    | -------------- | -------------------- | ------------------------------------------------------------------------- | 
    | dbPassword     | !                    | Means that the updated lambda function MUST NOT have an environment       |
    |                |                      | variable with the key "dbPassword" or it will be considered NON_COMPLIANT |
    | -------------- | -------------------- | ------------------------------------------------------------------------- | 
    | log_level      | !debug               | Means that the updated lambda function can have an environment variable   |
    |                |                      | with the key "log_level", but its value cannot be "debug"                 |
    | -------------- | -------------------- | ------------------------------------------------------------------------- | 
    | https_enabled  | true                 | Means that the updated lambda function MUST have an environment variable  |
    |                |                      | with the key "https_enabled", and its value MUST be "true"                |
    | -------------- | -------------------- | ------------------------------------------------------------------------- | 
    
 Feature:
    In order to: validate environment variables used on my lambda functions
             As: a Security Officer
         I want: To ensure that updated Lambdas have valid environment variables.
         
*/

const aws = require('aws-sdk');
const lambda = new aws.Lambda;
const config = new aws.ConfigService();

// This is where it's determined whether the resource is compliant or not.
function evaluateChangeNotificationCompliance(configurationItem, ruleParameters, event, callback) {
    if (!isApplicable(configurationItem, event)) {
        return callback(null, 'NOT_APPLICABLE');
    }
    checkDefined(configurationItem, 'configurationItem');
    checkDefined(configurationItem.configuration, 'configurationItem.configuration');
    checkDefined(ruleParameters, 'ruleParameters');
    
    if ('AWS::Lambda::Function' !== configurationItem.resourceType) {
        return callback(null, 'NOT_APPLICABLE');
    }

    getLambdaConfiguration(configurationItem.resourceId, (error, myEnvVariables) => {
        var envVariablesKeys = Object.keys(myEnvVariables);
        var filteredEnvVariablesKeys = envVariablesKeys.map(envVariablesKey => envVariablesKey.toLowerCase());
        var result = 'COMPLIANT';
        
        Object.keys(ruleParameters).forEach(function (key){
            var ruleParameterKey = key.toString().toLowerCase().trim();
            var ruleParameterValue = ruleParameters[key].toString().toLowerCase().trim();
            
            if(ruleParameterValue === '*' && !(envVariablesKeys.includes(ruleParameterKey))){
                //rule parameter config indicates mandatory env variable, which is not present
                result = 'NON_COMPLIANT';
                return;
            }
            
            if(ruleParameterValue === '!' && envVariablesKeys.includes(ruleParameterKey)){
                //rule parameter config indicates env variable shouldn't exist, and it is present
                result = 'NON_COMPLIANT';
                return;
            } 
            
            if(ruleParameterValue.startsWith('!') && envVariablesKeys.includes(ruleParameterKey) && 
                ruleParameterValue.substring(1) === myEnvVariables[ruleParameterKey].toString().toLowerCase().trim()){
                //rule parameter config indicates env variable shouldn't exist with this value, and it is present
                result = 'NON_COMPLIANT';
                return;
            }
            
            if(!envVariablesKeys.includes(ruleParameterKey)){
                //rule parameter config indicates env variable should exist and it is not present
                result = 'NON_COMPLIANT';
                return;
            } else if(ruleParameterValue !== myEnvVariables[ruleParameterKey].toString().toLowerCase().trim()){
                //rule parameter config indicates env variable should have this value, and it is different
                result = 'NON_COMPLIANT';
                return;
            }
        });
        return callback(null, result);
    });
}

function getLambdaConfiguration(resourceId, callback) {
    lambda.getFunctionConfiguration({ FunctionName: resourceId}, function(err, data) {
        if (err) {
            callback(err, null);
        }
        else {// successful response
            callback(null, data.Environment.Variables);
        }
    });
}

// Helper function used to validate input
function checkDefined(reference, referenceName) {
    if (!reference) {
        throw new Error(`Error: ${referenceName} is not defined`);
    }
    return reference;
}

// Check whether the message is OversizedConfigurationItemChangeNotification or not
function isOverSizedChangeNotification(messageType) {
    checkDefined(messageType, 'messageType');
    return messageType === 'OversizedConfigurationItemChangeNotification';
}

// Get configurationItem using getResourceConfigHistory API.
function getConfiguration(resourceType, resourceId, configurationCaptureTime, callback) {
    config.getResourceConfigHistory({ resourceType, resourceId, laterTime: new Date(configurationCaptureTime), limit: 1 }, (err, data) => {
        if (err) {
            callback(err, null);
        }
        const configurationItem = data.configurationItems[0];
        callback(null, configurationItem);
    });
}

// Convert from the API model to the original invocation model
/*eslint no-param-reassign: ["error", { "props": false }]*/
function convertApiConfiguration(apiConfiguration) {
    apiConfiguration.awsAccountId = apiConfiguration.accountId;
    apiConfiguration.ARN = apiConfiguration.arn;
    apiConfiguration.configurationStateMd5Hash = apiConfiguration.configurationItemMD5Hash;
    apiConfiguration.configurationItemVersion = apiConfiguration.version;
    apiConfiguration.configuration = JSON.parse(apiConfiguration.configuration);
    if ({}.hasOwnProperty.call(apiConfiguration, 'relationships')) {
        for (let i = 0; i < apiConfiguration.relationships.length; i++) {
            apiConfiguration.relationships[i].name = apiConfiguration.relationships[i].relationshipName;
        }
    }
    return apiConfiguration;
}

// Based on the type of message get the configuration item either from configurationItem in the invoking event or using the getResourceConfigHistiry API in getConfiguration function.
function getConfigurationItem(invokingEvent, callback) {
    checkDefined(invokingEvent, 'invokingEvent');
    if (isOverSizedChangeNotification(invokingEvent.messageType)) {
        const configurationItemSummary = checkDefined(invokingEvent.configurationItemSummary, 'configurationItemSummary');
        getConfiguration(configurationItemSummary.resourceType, configurationItemSummary.resourceId, configurationItemSummary.configurationItemCaptureTime, (err, apiConfigurationItem) => {
            if (err) {
                callback(err);
            }
            const configurationItem = convertApiConfiguration(apiConfigurationItem);
            callback(null, configurationItem);
        });
    } else {
        checkDefined(invokingEvent.configurationItem, 'configurationItem');
        callback(null, invokingEvent.configurationItem);
    }
}

// Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
function isApplicable(configurationItem, event) {
    checkDefined(configurationItem, 'configurationItem');
    checkDefined(event, 'event');
    const status = configurationItem.configurationItemStatus;
    const eventLeftScope = event.eventLeftScope;
    return (status === 'OK' || status === 'ResourceDiscovered') && eventLeftScope === false;
}

// This is the handler that's invoked by Lambda
// Most of this code is boilerplate; use as is
exports.handler = (event, context, callback) => {
    checkDefined(event, 'event');
    const invokingEvent = JSON.parse(event.invokingEvent);
    const ruleParameters = JSON.parse(event.ruleParameters);
    getConfigurationItem(invokingEvent, (err, configurationItem) => {
        if (err) {
            callback(err);
        }
        let compliance = 'NOT_APPLICABLE';
        const putEvaluationsRequest = {};
    
        // Invoke the compliance checking function.
        evaluateChangeNotificationCompliance(configurationItem, ruleParameters, event, (error, compliance) => {
            // Put together the request that reports the evaluation status
            putEvaluationsRequest.Evaluations = [
                {
                    ComplianceResourceType: configurationItem.resourceType,
                    ComplianceResourceId: configurationItem.resourceId,
                    ComplianceType: compliance,
                    OrderingTimestamp: configurationItem.configurationItemCaptureTime,
                },
            ];
            putEvaluationsRequest.ResultToken = event.resultToken;
    
            // Invoke the Config API to report the result of the evaluation
            config.putEvaluations(putEvaluationsRequest, (error, data) => {
                if (error) {
                    callback(error, null);
                } else if (data.FailedEvaluations.length > 0) {
                    // Ends the function execution if any evaluation results are not successfully reported.
                    callback(JSON.stringify(data), null);
                } else {
                    callback(null, data);
                }
            });
        });
    });
};
