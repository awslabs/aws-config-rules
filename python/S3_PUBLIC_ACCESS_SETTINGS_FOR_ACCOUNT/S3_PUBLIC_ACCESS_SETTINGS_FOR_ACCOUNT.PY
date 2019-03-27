#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
#

'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  S3_PUBLIC_ACCESS_SETTINGS_FOR_ACCOUNT
Description:
  Checks whether AWS S3 public access account settings match the assigned parameters.
Trigger:
  Periodic
Resource Type to report on:
  AWS::::Account
Rule Parameters:
  | ---------------------- | ---------- | ----------------------------------------------------------------------------------------|
  | Parameter Name         | Type       | Description                                                                             |
  | ---------------------- | ---------- | ----------------------------------------------------------------------------------------|
  | BlockPublicAcls        | Mandatory  | Block new public ACLs and uploading public objects (True/False)                         |
  | IgnorePublicAcls       | Mandatory  | Remove public access granted through public ACLs (True/False)                           |
  | BlockPublicPolicy      | Mandatory  | Block new public bucket policies (True/False)                                           |
  | RestrictPublicBuckets  | Mandatory  | Block public and cross-account access to buckets that have public policies (True/False) |
  | ---------------------- | ---------- | ----------------------------------------------------------------------------------------|
Feature:
  In order to: ensure that s3 account settings are being restricted to the appropriate level
           As: a Security Officer
       I want: to verify that the configuration of s3 account public access settings is correct.
Scenarios:
  Scenario 1:
    Given: config parameters are defined for the config rule
      And: At least 1 S3 config parameter does not match the corresponding value for the account
     then: Return NON_COMPLIANT
  Scenario 2:
    Given: config parameters are defined for the config rule
      And: All S3 config parameters match the corresponding value for the account
     then: Return COMPLIANT
'''

import json
import datetime
import os
import os.path
import sys
envLambdaTaskRoot = os.environ["LAMBDA_TASK_ROOT"]  
sys.path.insert(0,envLambdaTaskRoot+"/boto3-1-9-82") #hack to change the version of boto
import boto3
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

#############
# Main Code #
#############

def evaluate_compliance(event, configuration_item, valid_rule_parameters):
  
    client = boto3.client('s3control')
    response = client.get_public_access_block(AccountId=event['accountId'])
    evaluations = []
    annotationbuilder = ''

    if (response['PublicAccessBlockConfiguration']['BlockPublicAcls'] == valid_rule_parameters['BlockPublicAcls']) \
    and (response['PublicAccessBlockConfiguration']['IgnorePublicAcls'] == valid_rule_parameters['IgnorePublicAcls']) \
    and (response['PublicAccessBlockConfiguration']['BlockPublicPolicy'] == valid_rule_parameters['BlockPublicPolicy']) \
    and (response['PublicAccessBlockConfiguration']['RestrictPublicBuckets'] == valid_rule_parameters['RestrictPublicBuckets']):
        annotationbuilder = 'BlockPublicAcls:' + str(response['PublicAccessBlockConfiguration']['BlockPublicAcls']) + ' ' \
        'IgnorePublicAcls:' + str(response['PublicAccessBlockConfiguration']['IgnorePublicAcls']) + ' ' \
        'BlockPublicPolicy:' + str(response['PublicAccessBlockConfiguration']['BlockPublicPolicy']) + ' ' \
        'RestrictPublicBuckets:' + str(response['PublicAccessBlockConfiguration']['RestrictPublicBuckets'])
        evaluations.append(build_evaluation(event['accountId'], 'COMPLIANT', event))

    else:
        annotationbuilder = 'BlockPublicAcls:' + str(response['PublicAccessBlockConfiguration']['BlockPublicAcls']) + ' ' \
        'IgnorePublicAcls:' + str(response['PublicAccessBlockConfiguration']['IgnorePublicAcls']) + ' ' \
        'BlockPublicPolicy:' + str(response['PublicAccessBlockConfiguration']['BlockPublicPolicy']) + ' ' \
        'RestrictPublicBuckets:' + str(response['PublicAccessBlockConfiguration']['RestrictPublicBuckets'])
        evaluations.append(build_evaluation(event['accountId'], 'NON_COMPLIANT', event, annotation=annotationbuilder))
    return evaluations

def evaluate_parameters(rule_parameters):

    valid_rule_parameters = {}

    if 'BlockPublicAcls' not in rule_parameters:
        raise ValueError('The parameter "BlockPublicAcls" must be configured.')
    if 'IgnorePublicAcls' not in rule_parameters:
        raise ValueError('The parameter "IgnorePublicAcls" must be configured.')
    if 'BlockPublicPolicy' not in rule_parameters:
        raise ValueError('The parameter "BlockPublicPolicy" must be configured.')
    if 'RestrictPublicBuckets' not in rule_parameters:
        raise ValueError('The parameter "RestrictPublicBuckets" must be configured.')
    valid_rule_parameters['BlockPublicAcls'] = to_bool(rule_parameters['BlockPublicAcls'])
    valid_rule_parameters['IgnorePublicAcls'] = to_bool(rule_parameters['IgnorePublicAcls'])
    valid_rule_parameters['BlockPublicPolicy'] = to_bool(rule_parameters['BlockPublicPolicy'])
    valid_rule_parameters['RestrictPublicBuckets'] = to_bool(rule_parameters['RestrictPublicBuckets'])

    return valid_rule_parameters

####################
# Helper Functions #
####################

def to_bool(value):
    """
    Convert input string into a boolean. Throw exception if it gets a string it doesn't handle.
    Case is ignored for strings. These string values are handled:
    True: 'True', "1", "TRue", "yes", "y", "t"
    False: "", "0", "faLse", "no", "n", "f"
    Non-string values are passed to bool.
    """
    if type(value) == type(''):
        if value.lower() in ("yes", "y", "true",  "t", "1"):
            return True
        if value.lower() in ("no",  "n", "false", "f", "0", ""):
            return False
        raise Exception('Invalid value for boolean conversion: ' + value)
    return bool(value)

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):

    return  build_error_response(internalErrorMessage="Parameter value is invalid",
                                 internalErrorDetails="An ValueError was raised during the validation of the Parameter value",
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):

    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):

    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc

def build_evaluation_from_config_item(configuration_item, compliance_type, annotation=None):

    eval_ci = {}
    if annotation:
        eval_ci['Annotation'] = annotation
    eval_ci['ComplianceResourceType'] = configuration_item['resourceType']
    eval_ci['ComplianceResourceId'] = configuration_item['resourceId']
    eval_ci['ComplianceType'] = compliance_type
    eval_ci['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
    return eval_ci

####################
# Boilerplate Code #
####################

# Helper function used to validate input
def check_defined(reference, reference_name):
    if not reference:
        raise Exception('Error: ', reference_name, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'OversizedConfigurationItemChangeNotification'

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(message_type):
    check_defined(message_type, 'messageType')
    return message_type == 'ScheduledNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resource_type, resource_id, configuration_capture_time):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resource_type,
        resourceId=resource_id,
        laterTime=configuration_capture_time,
        limit=1)
    configurationItem = result['configurationItems'][0]
    return convert_api_configuration(configurationItem)

# Convert from the API model to the original invocation model
def convert_api_configuration(configurationItem):
    for k, v in configurationItem.items():
        if isinstance(v, datetime.datetime):
            configurationItem[k] = str(v)
    configurationItem['awsAccountId'] = configurationItem['accountId']
    configurationItem['ARN'] = configurationItem['arn']
    configurationItem['configurationStateMd5Hash'] = configurationItem['configurationItemMD5Hash']
    configurationItem['configurationItemVersion'] = configurationItem['version']
    configurationItem['configuration'] = json.loads(configurationItem['configuration'])
    if 'relationships' in configurationItem:
        for i in range(len(configurationItem['relationships'])):
            configurationItem['relationships'][i]['name'] = configurationItem['relationships'][i]['relationshipName']
    return configurationItem

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    if is_oversized_changed_notification(invokingEvent['messageType']):
        configurationItemSummary = check_defined(invokingEvent['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configurationItemSummary['resourceType'], configurationItemSummary['resourceId'], configurationItemSummary['configurationItemCaptureTime'])
    elif is_scheduled_notification(invokingEvent['messageType']):
        return None
    return check_defined(invokingEvent['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    try:
        check_defined(configurationItem, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configurationItem['configurationItemStatus']
    eventLeftScope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        print(str(ex))
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# This removes older evaluation (usually useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):

    cleaned_evaluations = []

    old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=event['configRuleName'],
        ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
        Limit=100)

    old_eval_list = []

    while True:
        for old_result in old_eval['EvaluationResults']:
            old_eval_list.append(old_result)
        if 'NextToken' in old_eval:
            next_token = old_eval['NextToken']
            old_eval = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
                ConfigRuleName=event['configRuleName'],
                ComplianceTypes=['COMPLIANT', 'NON_COMPLIANT'],
                Limit=100,
                NextToken=next_token)
        else:
            break

    for old_eval in old_eval_list:
        old_resource_id = old_eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        newer_founded = False
        for latest_eval in latest_evaluations:
            if old_resource_id == latest_eval['ComplianceResourceId']:
                newer_founded = True
        if not newer_founded:
            cleaned_evaluations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evaluations + latest_evaluations

# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT

    #print(event)
    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    try:
        valid_rule_parameters = evaluate_parameters(rule_parameters)
    except ValueError as ex:
        return build_parameters_value_error_response(ex)

    try:
        AWS_CONFIG_CLIENT = get_client('config', event)
        if invoking_event['messageType'] in ['ConfigurationItemChangeNotification', 'ScheduledNotification', 'OversizedConfigurationItemChangeNotification']:
            configuration_item = get_configuration_item(invoking_event)
            if is_applicable(configuration_item, event):
                compliance_result = evaluate_compliance(event, configuration_item, valid_rule_parameters)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return build_internal_error_response('Unexpected message type', str(invoking_event))
    except botocore.exceptions.ClientError as ex:
        if is_internal_error(ex):
            return build_internal_error_response("Unexpected error while completing API request", str(ex))
        return build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'], ex.response['Error']['Message'])
    except ValueError as ex:
        return build_internal_error_response(str(ex), str(ex))

    evaluations = []
    latest_evaluations = []

    if not compliance_result:
        latest_evaluations.append(build_evaluation(event['accountId'], "NOT_APPLICABLE", event, resource_type='AWS::::Account'))
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, str):
        if configuration_item:
            evaluations.append(build_evaluation_from_config_item(configuration_item, compliance_result))
        else:
            evaluations.append(build_evaluation(event['accountId'], compliance_result, event, resource_type=DEFAULT_RESOURCE_TYPE))
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True

            if not missing_fields:
                latest_evaluations.append(evaluation)
        evaluations = clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, dict):
        missing_fields = False
        for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)
    else:
        evaluations.append(build_evaluation_from_config_item(configuration_item, 'NOT_APPLICABLE'))

    # Put together the request that reports the evaluation status
    resultToken = event['resultToken']
    testMode = False
    if resultToken == 'TESTMODE':
        # Used solely for RDK test to skip actual put_evaluation API call
        testMode = True
    # Invoke the Config API to report the result of the evaluation
    AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluations, ResultToken=resultToken, TestMode=testMode)
    # Used solely for RDK test to be able to test Lambda function
    return evaluations

def is_internal_error(exception):
    return ((not isinstance(exception, botocore.exceptions.ClientError)) or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code'] or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internalErrorMessage, internalErrorDetails=None):
    return build_error_response(internalErrorMessage, internalErrorDetails, 'InternalError', 'InternalError')

def build_error_response(internalErrorMessage, internalErrorDetails=None, customerErrorCode=None, customerErrorMessage=None):
    error_response = {
        'internalErrorMessage': internalErrorMessage,
        'internalErrorDetails': internalErrorDetails,
        'customerErrorMessage': customerErrorMessage,
        'customerErrorCode': customerErrorCode
    }
    print(error_response)
    return error_response
