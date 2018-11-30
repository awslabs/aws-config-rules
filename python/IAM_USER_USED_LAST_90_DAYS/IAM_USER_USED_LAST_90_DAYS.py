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
    IAM_USER_USED_LAST_90_DAYS

Description:
    Check if IAM users have been active for last N days (default 90)

Trigger:
    Periodic
    Change Trigger on AWS::IAM::User

Resource Type to report on:
    AWS::IAM::User

Rule Parameters:
  | --------------------- | --------- | ---------------------------------------- |-------------------------|
  | Parameter Name        | Type      | Description                              | Notes                   |
  | --------------------- | --------- | ---------------------------------------- |-------------------------|
  | WhitelistedUserList   | Optional  | Represents the IAM users which are       | Seperated by comma (,)  |
  |                       |           | exempted from being active.              |                         |
  | --------------------- | --------- | ---------------------------------------- |-------------------------|
  | NotUsedTimeOutInDays  | Optional  | Maximum time without activity.           | The default value is 90 |
  | --------------------- | --------- | -----------------------------------------|-------------------------|
  | NewUserCooldownInDays | Optional  | Minimun time after creation before       | The default value is 7  |
  |                       |           | evaluating.                              |                         |
  | --------------------- | --------- | -----------------------------------------|-------------------------|

Feature:
  In order to: enforce security best practices for IAM users
           As: a Security Officer
       I want: To ensure that IAM users are never left unused, except if whitelisted

Scenarios:

  Scenario: 1
    Given: A periodic trigger
      And: No IAM Users
     Then: Return Not Applicable

  Scenario: 2
    Given: WhitelistedUserList is not empty
      And: A user listed in WhitelistedUserList is not an alphanumerical string starting with "AIDA"
     Then: Return an error

  Scenario: 3
    Given: NotUsedTimeOutInDays is not empty
      And: NotUsedTimeOutInDays is not a positive interger
     Then: Return an error

  Scenario: 4
    Given: A list of IAM users
      And: WhitelistedUserList is configured and valid
      And: The IAM User UniqueID is listed in WhitelistedUserList
     Then: Return Compliant

  Scenario: 5
    Given: A list of IAM users
      And: <Options of Whitelist>
      And: The IAM User has <Options of Access>
      And: The IAM User has logged at least once in the past <Options of TimeoutDays> days
     Then: Return Compliant

    With:
        | Options of Whitelist                                                                                          |
        | WhitelistedUserList is configured and valid (And) The IAM User UniqueID is not listed in WhitelistedUserList  |
        | WhitelistedUserList is not configured                                                                         |
    
        | Options of Access     |
        | Programmatic Access   |
        | Console Access        |
        | Both                  |
        
        | Options of TimeoutDays                                |
        | NotUsedTimeOutInDays is configured and valid          |
        | NotUsedTimeOutInDays is not configured : 90 (default) |   

  Scenario: 6
    Given: A list of IAM users
      And: <Options of Whitelist>
      And: The IAM User has <Options of Access>
      And: The IAM User has not logged at least once in the past <Options of TimeoutDays> days
     Then: Return Non Compliant

    With:
        | Options of Whitelist                                                                                          |
        | WhitelistedUserList is configured and valid (And) The IAM User UniqueID is not listed in WhitelistedUserList  |
        | WhitelistedUserList is not configured                                                                         |
    
        | Options of Access     |
        | Programmatic Access   |
        | Console Access        |
        | Both                  |
        
        | Options of TimeoutDays                                |
        | NotUsedTimeOutInDays is configured and valid          |
        | NotUsedTimeOutInDays is not configured : 90 (default) |
'''

import json
import boto3
import botocore
import datetime
from dateutil.tz import tzutc
import dateutil.parser
from datetime import timedelta
import re
# import liblogging
# logger = logging.getLogger()

AWS_CONFIG_CLIENT = boto3.client('config')

DEFAULT_RESOURCE_TYPE = "AWS::IAM::User"
ASSUME_ROLE_MODE = False

def build_invalid_integer_error_response(exception):
    return build_error_response(internalErrorMessage="Customer error while parsing input parameters",
                                internalErrorDetails=str(exception),
                                customerErrorCode="InvalidParameterValueException",
                                customerErrorMessage="Parameter 'NotUsedTimeOutInDays' is not a valid integer.")

 
def build_unsupported_expiration_days_error_response():
    return  build_error_response(internalErrorMessage="Customer error while parsing input parameters",
                                 internalErrorDetails="Parameter value is greater than supported value",
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage="Value of parameter 'NotUsedTimeOutInDays' is not valid. Use a value between 0 and 999999999, and try again.")

def build_invalid_str_error_response(exception):
    return  build_error_response(internalErrorMessage="Customer error while parsing input parameters",
                                 internalErrorDetails=str(exception),
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage="Value of parameter 'WhitelistedUserList' is not valid.")
            
def validate_whitelist(list):
    for user in list:
        if not user.isupper():
            raise ValueError("All whitelisted IAM users ID must be in upper format (e.g. AIDA12345ABCDE6789012).")
        if not user.isalnum():
            raise ValueError("All whitelisted IAM users ID must be in alphanumerical format (e.g. AIDA12345ABCDE6789012).")
        elif user[0:4] != 'AIDA':
            raise ValueError("All whitelisted IAM users ID must be starting with 'AIDA' (e.g. AIDA12345ABCDE6789012).")

def is_older_than(date, days):
    expiry_time = timedelta(days=days)
    today = datetime.datetime.now(tz=tzutc())
    time_delta = today - date
    if expiry_time > time_delta:
        return True
    return False 
        
def evaluate_changetrigger_compliance(event, configuration_item, rule_parameters):

    evaluations = []
    iam_client = get_client('iam', event)
        
    if configuration_item['resourceId'] in rule_parameters['WhitelistedUserList']:
        return 'COMPLIANT'

    creation_date = parse_time(configuration_item['configuration']['createDate'])
    if is_older_than(creation_date, rule_parameters['NewUserCooldownInDays']):
        return 'COMPLIANT'

    user = iam_client.get_user(UserName=configuration_item['resourceName'])['User']
    if is_password_used_recently(user, rule_parameters['NotUsedTimeOutInDays']):
        return 'COMPLIANT'

    if is_access_keys_used_recently(iam_client, configuration_item['resourceName'], rule_parameters['NotUsedTimeOutInDays']):
        return 'COMPLIANT'
    
    return 'NON_COMPLIANT'

def parse_time(time_string):
    return dateutil.parser.parse(time_string).replace(tzinfo=dateutil.tz.tzutc())

def is_password_used_recently(user, NotUsedTimeOutInDays):
    if 'PasswordLastUsed' in user \
        and user['PasswordLastUsed'] \
        and is_older_than(user['PasswordLastUsed'], NotUsedTimeOutInDays):
        return True
    return False

def is_access_keys_used_recently(iam_client, username, NotUsedTimeOutInDays):
    access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
    for access_key in access_keys:
        last_used_date = iam_client.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])['AccessKeyLastUsed']
        if 'LastUsedDate' in last_used_date and is_older_than(last_used_date['LastUsedDate'], NotUsedTimeOutInDays):
            return True
    return False

def evaluate_scheduled_compliance(event, configuration_item, rule_parameters):

    evaluations = []
    iam_client = get_client('iam', event)
    
    users_list = iam_client.list_users()
    
    while True:
        for user in users_list['Users']:

            if user['UserId'] in rule_parameters['WhitelistedUserList']:
                evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event))
                continue

            if is_older_than(user['CreateDate'], rule_parameters['NewUserCooldownInDays']):
                evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event))
                continue

            if is_password_used_recently(user, rule_parameters['NotUsedTimeOutInDays']):
                evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event))
                continue

            if is_access_keys_used_recently(iam_client, user['UserName'], rule_parameters['NotUsedTimeOutInDays']):
                evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event))
                continue

            evaluations.append(build_evaluation(user['UserId'], 'NON_COMPLIANT', event))

        if "Marker" in users_list:
                users_list = iam_client.list_users(Marker=users_list["Marker"])
        else:
            break

    if not evaluations:
        evaluations.append(build_evaluation(event['accountId'],'NOT_APPLICABLE', event, resource_type='AWS::::Account'))
    return evaluations

# USE AS IS
# Helper function to check if rule parameters exist
def parameters_exist(parameters):
    return len(parameters) != 0

# Helper function used to validate input
def check_defined(reference, referenceName):
    if not reference:
        raise Exception('Error: ', referenceName, 'is not defined')
    return reference

# Check whether the message is OversizedConfigurationItemChangeNotification or not
def is_oversized_changed_notification(messageType):
    check_defined(messageType, 'messageType')
    return messageType == 'OversizedConfigurationItemChangeNotification'

# Check whether the message is a ScheduledNotification or not.
def is_scheduled_notification(messageType):
    check_defined(messageType, 'messageType')
    return messageType == 'ScheduledNotification'

# Get configurationItem using getResourceConfigHistory API
# in case of OversizedConfigurationItemChangeNotification
def get_configuration(resourceType, resourceId, configurationCaptureTime):
    result = AWS_CONFIG_CLIENT.get_resource_config_history(
        resourceType=resourceType,
        resourceId=resourceId,
        laterTime=configurationCaptureTime,
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

def check_valid_notification(invoking_event):
    if 'messageType' not in invoking_event:
        raise ValueError('Error: messageType is not defined in event.')
    if invoking_event['messageType'] not in ['ConfigurationItemChangeNotification', 'ScheduledNotification', 'OversizedConfigurationItemChangeNotification']:
        raise ValueError('Error: messageType is an expected type.')

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invokingEvent):
    check_defined(invokingEvent, 'invokingEvent')
    check_valid_notification(invokingEvent)
    if is_oversized_changed_notification(invokingEvent['messageType']):
        configurationItemSummary = check_defined(invokingEvent['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configurationItemSummary['resourceType'], configurationItemSummary['resourceId'], configurationItemSummary['configurationItemCaptureTime'])
    elif is_scheduled_notification(invokingEvent['messageType']):
        return None
    return check_defined(invokingEvent['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    check_defined(configurationItem, 'configurationItem')
    check_defined(event, 'event')
    status = configurationItem['configurationItemStatus']
    eventLeftScope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")
    return (status == 'OK' or status == 'ResourceDiscovered') and not eventLeftScope

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event=None):
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

def get_assume_role_credentials(role_arn):
    sts_client = boto3.client('sts')
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="configLambdaExecution")
        return assume_role_response['Credentials']
    except botocore.exceptions.ClientError as ex:
        # Scrub error message for any internal account info leaks
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    eval = {}
    if annotation:
        eval['Annotation'] = annotation
    eval['ComplianceResourceType'] = resource_type
    eval['ComplianceResourceId'] = resource_id
    eval['ComplianceType'] = compliance_type
    eval['OrderingTimestamp'] = str(json.loads(event['invokingEvent'])['notificationCreationTime'])
    return eval

def build_evaluation_from_config_item(configuration_item, compliance_type, annotation=None):
    eval_ci = {}
    if annotation:
        eval_ci['Annotation'] = annotation
    eval_ci['ComplianceResourceType'] = configuration_item['resourceType']
    eval_ci['ComplianceResourceId'] = configuration_item['resourceId']
    eval_ci['ComplianceType'] = compliance_type
    eval_ci['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
    return eval_ci

# This removes older evaluation (useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):
    
    cleaned_evalations = []

    old_evaluations = AWS_CONFIG_CLIENT.get_compliance_details_by_config_rule(
        ConfigRuleName=event['configRuleName'], 
        ComplianceTypes=['COMPLIANT','NON_COMPLIANT'],
        Limit=100)['EvaluationResults']
    
    for old_eval in old_evaluations:
        old_resource_id = old_eval['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
        newer_founded = False
        for latest_eval in latest_evaluations:
            if old_resource_id == latest_eval['ComplianceResourceId']:
                newer_founded = True
        if not newer_founded:
            cleaned_evalations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evalations + latest_evaluations

# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT
    try:
        if ASSUME_ROLE_MODE:
            AWS_CONFIG_CLIENT = get_client('config', event)
    except Exception as ex:
        return build_error_response('Encountered error while making API request',
                                    str(ex),
                                    ex.response['Error']['Code'],
                                    ex.response['Error']['Message']
                                   )
        
    # liblogging.logEvent(event)

    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    expiration_days = 90  # default
    if 'NotUsedTimeOutInDays' in rule_parameters:
        try:
            expiration_days = int(str(rule_parameters['NotUsedTimeOutInDays']))
        except ValueError as ex:
            return build_invalid_integer_error_response(ex)
        
    if expiration_days < 0 or expiration_days > 999999999:  # max value supported by time delta function
        return build_unsupported_expiration_days_error_response() 

    new_user_cool_down = 7  # default
    if 'NewUserCooldownInDays' in rule_parameters:
        try:
            new_user_cool_down = int(str(rule_parameters['NewUserCooldownInDays']))
        except ValueError as ex:
            return build_invalid_integer_error_response(ex)

    whilelist_list = [] # default
    if 'WhitelistedUserList' in rule_parameters:
        try: 
            whilelist_list = rule_parameters['WhitelistedUserList'].replace(', ',',').split(',')
            validate_whitelist(whilelist_list)
        except AttributeError as ex:
            return build_invalid_str_error_response(ex)
        except ValueError as ex:
            return build_invalid_str_error_response(ex)
    
    rule_parameters = {
        'NotUsedTimeOutInDays': expiration_days,
        'WhitelistedUserList': whilelist_list,
        'NewUserCooldownInDays': new_user_cool_down
        }
    
    try:
        configuration_item = get_configuration_item(invoking_event)
        if invoking_event['messageType'] == 'ConfigurationItemChangeNotification':
            # liblogging.logCIMetadata(event)
            compliance_result = evaluate_changetrigger_compliance(event, configuration_item, rule_parameters)
        elif invoking_event['messageType'] == 'ScheduledNotification':
            compliance_result = evaluate_scheduled_compliance(event, configuration_item, rule_parameters)
        else:
            return {'internalErrorMessage': 'Unexpected message type ' + str(invoking_event)}
    except botocore.exceptions.ClientError as ex:
        if is_internal_error(ex):
            return build_internal_error_response("Unexpected error while completing API request", str(ex))
        else:
            return build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'],
                ex.response['Error']['Message'])
    except ValueError as ex:
        return build_internal_error_response(str(ex), str(ex))
    
    evaluations = []
    latest_evaluations = []
    
    if isinstance(compliance_result, str):
        evaluations.append(build_evaluation_from_config_item(configuration_item, compliance_result))
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
    return {
        'internalErrorMessage': internalErrorMessage,
        'internalErrorDetails': internalErrorDetails,
        'customerErrorMessage': customerErrorMessage,
        'customerErrorCode': customerErrorCode
    }