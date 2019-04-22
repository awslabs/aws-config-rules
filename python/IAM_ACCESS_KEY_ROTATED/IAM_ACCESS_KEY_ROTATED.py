#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
'''
#####################################
##           Gherkin               ##
#####################################


 Rule Name:
   IAM_ACCESS_KEY_ROTATED

 Description:
   To check IAM users access key are rotated by a specific number of days (by default 90 days).

 Trigger:
   Periodic

 Reports on:
   AWS::IAM::User

 Rule Parameters:
   | ---------------------- | --------- | -------------------------------------------------------- |
   | Parameter Name         | Type      | Description                                              |
   | ---------------------- | --------- | -------------------------------------------------------- |
   | WhitelistedUserList    | Optional  | Represents the IAM users which are exempted from the IAM |
   |                        |           | Config rule. The valid users in this list will be        |
   |                        |           | compliant by default.                                    |
   |                        |           | List of all the UniqueID (user ID) separated by a comma. |
   | ---------------------- | --------- | -------------------------------------------------------- |
   | KeyKeyActiveTimeOutInDays | Optional  | Numeric variable representing the maximum age in days of |
   |                        |           | access key. The default value is 90.                     |
   | ---------------------- | --------- | -------------------------------------------------------- |


 Feature:
   In order to: enforce security best practices for IAM users
           As: a Security Officer
       I want: To ensure that IAM users are never left active, except if whitelisted

 Scenarios:

  Scenario: 1
     Given: No IAM Users
      Then: Return "NOT_APPLICABLE"

   Scenario: 2
     Given: WhitelistedUserList is configured
       And: A user listed in WhitelistedUserList is not an alphanumerical string starting with "AIDA"
      Then: Return an error

   Scenario: 3
     Given: KeyKeyActiveTimeOutInDays is configured
       And: KeyKeyActiveTimeOutInDays is not a positive integer smaller than 999999999
      Then: Return an error

   Scenario: 4
     Given: An IAM user
       And: WhitelistedUserList is configured and valid
       And: The IAM user is listed on the WhitelistedUserList
      Then: Return COMPLIANT

   Scenario: 5
     Given: An IAM user
       And: The IAM User has no access keys
      Then: Return COMPLIANT

   Scenario: 6
     Given: An IAM user
       And: The IAM User has no active access keys
      Then: Return COMPLIANT

   Scenario: 7
     Given: An IAM user
       And: The IAM user is not listed on the WhitelistedUserList, if configured
       And: The IAM user has one or more active access keys
       And: The oldest key age is more or equal than KeyKeyActiveTimeOutInDays, if configured (or default, if not configured)
      Then: return NON_COMPLIANT

   Scenario: 8
     Given: An IAM user
       And: The IAM user is not listed on the WhitelistedUserList, if configured
       And: The IAM user has one or more active access keys
       And: The oldest key age is less than KeyKeyActiveTimeOutInDays, if configured (or default, if not configured)
      Then: return COMPLIANT
'''

import json
from datetime import datetime, timedelta
import dateutil.parser
import re
import boto3
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'
DEFAULT_NUMBER_OF_DAYS = 90

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

#############
# Main Code #
#############

def evaluate_compliance(event, configuration_item, valid_rule_parameters):
    """Form the evaluation(s) to be return to Config Rules

    Return either:
    None -- when no result needs to be displayed
    a string -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    a dictionary -- the evaluation dictionary, usually built by build_evaluation_from_config_item()
    a list of dictionary -- a list of evaluation dictionary , usually built by build_evaluation()

    Keyword arguments:
    event -- the event variable given in the lambda handler
    configuration_item -- the configurationItem dictionary in the invokingEvent
    valid_rule_parameters -- the output of the evaluate_parameters() representing validated parameters of the Config Rule

    Advanced Notes:
    1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status, the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
    2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
    3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
    """

    iam_client = get_client('iam', event)
    evaluations = []

    users_list = get_all_users(iam_client)

    if not users_list:
        return None

    for user in users_list:
        if user['UserId'] in valid_rule_parameters['WhitelistedUserList']:
            evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event, annotation='This user ({}) is whitelisted.'.format(user['UserId'])))
            continue
        keys_list = iam_client.list_access_keys(UserName=user['UserName'])
        expired_key = False
        for key in keys_list['AccessKeyMetadata']:
            if key['Status'] == 'Inactive':
                continue
            if not is_key_still_valid(key['CreateDate'], valid_rule_parameters['KeyActiveTimeOutInDays']):
                expired_key = True
                evaluations.append(build_evaluation(user['UserId'], 'NON_COMPLIANT', event, annotation='This user ({}) has an expired active access key ({}). The key is older than {}. It must be no older than {} days.'.format(user['UserId'], key['AccessKeyId'], str(key_age(key['CreateDate'])).split(',')[0], valid_rule_parameters['KeyActiveTimeOutInDays'])))
                break
        if not expired_key:
            evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event))

    return evaluations

def get_all_users(client):
    list_to_return = []
    user_list = client.list_users()
    while True:
        for user in user_list['Users']:
            list_to_return.append(user)
        if 'Marker' in user_list:
            user_list = client.list_users(Marker=user_list['Marker'])
        else:
            break
    return list_to_return

def is_key_still_valid(create_date, timeout_days):
    expiry_time = timedelta(days=timeout_days)
    if expiry_time > key_age(create_date):
        return True
    return False

def key_age(create_date):
    today = datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc())
    time_delta = today - create_date
    return time_delta    

def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """

    valid_rule_parameters = {}

    valid_rule_parameters['WhitelistedUserList'] = []
    if 'WhitelistedUserList' in rule_parameters:
        whitelisted_users = rule_parameters['WhitelistedUserList'].replace(' ', '').split(',')
        valid_whitelist = []
        for whitelisted_user in whitelisted_users:
            if not re.match("^AIDA[A-Z0-9]+$", whitelisted_user):
                raise ValueError('Invalid Parameter WhitelistedUser: ' + whitelisted_user)
            valid_whitelist.append(whitelisted_user)
        valid_rule_parameters['WhitelistedUserList'] = valid_whitelist

    valid_rule_parameters['KeyActiveTimeOutInDays'] = DEFAULT_NUMBER_OF_DAYS
    if 'KeyActiveTimeOutInDays' in rule_parameters:
        try:
            valid_rule_parameters['KeyActiveTimeOutInDays'] = int(str(rule_parameters['KeyActiveTimeOutInDays']))
        except:
            raise ValueError("Invalid Parameter KeyActiveTimeOutInDays: not an integer.")

    if valid_rule_parameters['KeyActiveTimeOutInDays'] < 0:
        raise ValueError("Invalid Parameter KeyActiveTimeOutInDays: use a positive value.")

    if valid_rule_parameters['KeyActiveTimeOutInDays'] > 999999999:
        raise ValueError("Invalid Parameter KeyActiveTimeOutInDays: use a value less than 999999999.")

    return valid_rule_parameters

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.
    Keyword arguments:
    ex -- Exception text
    """
    return build_error_response(internalErrorMessage="Parameter value is invalid",
                                 internalErrorDetails="An ValueError was raised during the validation of the Parameter value",
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.

    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None)
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = annotation
    eval_cc['ComplianceResourceType'] = resource_type
    eval_cc['ComplianceResourceId'] = resource_id
    eval_cc['ComplianceType'] = compliance_type
    eval_cc['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval_cc

def build_evaluation_from_config_item(configuration_item, compliance_type, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on configuration change rules.

    Keyword arguments:
    configuration_item -- the configurationItem dictionary in the invokingEvent
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    annotation -- an annotation to be added to the evaluation (default None)
    """
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
    evaluation_copy = []
    evaluation_copy = evaluations[:]
    while(evaluation_copy):
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluation_copy[:100], ResultToken=resultToken, TestMode=testMode)
        del evaluation_copy[:100]
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
