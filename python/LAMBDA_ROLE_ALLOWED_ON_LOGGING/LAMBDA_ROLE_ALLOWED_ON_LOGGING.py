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
  LAMBDA_ROLE_ALLOWED_ON_LOGGING

Description:
    Ensure Lambda has the permission for logging. Each Lambda functions should have an IAM role with appropriate IAM permissions to publish its Lambda function logs to CloudWatch.

Trigger:
  Configuration Change on AWS::Lambda::Function

Reports on:
  AWS::Lambda::Function

Rule Parameters:
  None

Feature:
  In order to: ensure that role attached to any Lambda has permissions to create log events in CloudWatch log group
           As: a Security Officer
       I want: to ensure that any policy associated with role of Lambda has either 1) * (admin), 2) logs:* or 3) "logs:CreateLogGroup", "logs:CreateLogStream","logs:PutLogEvents" check these individual permissions.

Scenarios:

  Scenario: 1
    Given: A Lambda is deleted
     Then: Return NOT_APPLICABLE

  Scenario: 2
    Given: A Lambda Role with the AWS-managed policy named "AWSLambdaBasicExecutionRole"
     Then: Return COMPLIANT

  Scenario: 3
    Given: A Lambda Role with no <Policy>
     Then: Return NON_COMPLIANT

  Scenario: 4
    Given: At least one <Policy> statement of Lambda Role has Action as "*" 
      And: The resource-level condition is either * or arn:aws:logs:*
     Then: Return COMPLIANT

  Scenario: 5
    Given: At least one <Policy> statement of Lambda Role has Action as "logs:*""
      And: The resource-level condition is either * or arn:aws:logs:*
     Then: Return COMPLIANT

  Scenario: 6
    Given: At least one <Policy> statement of Lambda Role has Action as "logs:CreateLogGroup", "logs:CreateLogStream" and "logs:PutLogEvents" 
      And: The resource-level condition is either * or arn:aws:logs:*
     Then: Return COMPLIANT

  Scenario: 7
    Given: Scenario 4/5/6 are not happening
     Then: Return NON_COMPLIANT

  Examples:
    | Policy             |
    | inline user policy |
    | aws managed policy |

Blind spot:
    1) If the trust policy of the IAM Role is not allowing Lambda
    2) A combinaison of policies gives the proper permissions.
    3) A combinaison of inline and managed policies gives the proper permissions.
    4) More than 100 policies are attached on role
    5) Explicit Deny are not covered
    6) NotAction are not covered
'''

import json
import datetime
import fnmatch
import re
import boto3
import botocore.exceptions

AWS_CONFIG_CLIENT = boto3.client('config')

DEFAULT_RESOURCE_TYPE = "AWS::Lambda::Function"
ASSUME_ROLE_MODE = True

def evaluate_compliance(configuration_item, rule_parameters):

    role = configuration_item['relationships'][0]['resourceName']
    try:
        attachedpolicies = IAM_CLIENT.list_attached_role_policies(RoleName=role)
        if attachedpolicies['AttachedPolicies']:
            for policy in attachedpolicies['AttachedPolicies']:
                if policy['PolicyArn'] == "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole":
                    return 'COMPLIANT'
            if is_a_role_managed_policy_allow_logging(attachedpolicies['AttachedPolicies']):
                return 'COMPLIANT'

        inlinepolicies = IAM_CLIENT.list_role_policies(RoleName=role)
        if inlinepolicies['PolicyNames']:
            if is_a_role_inline_policy_allow_logging(role, inlinepolicies['PolicyNames']):
                return 'COMPLIANT'

    except Exception as e:
        print("Exception:" + str(e) + "\nFunction: " + configuration_item['configuration']['functionName'])
        raise

    return 'NON_COMPLIANT'

def is_a_role_inline_policy_allow_logging(roleName, inlinepolicies):

    for policy in inlinepolicies:
        getrolepolicy = IAM_CLIENT.get_role_policy(RoleName=roleName, PolicyName=policy)
        statements = getrolepolicy['PolicyDocument']['Statement']
        if are_statements_allow_logging(statements):
            return True

    return False

def is_a_role_managed_policy_allow_logging(managedpolicies):

    for policy in managedpolicies:
        getrolepolicy = IAM_CLIENT.get_policy(PolicyArn=policy['PolicyArn'])
        getpolicyversion = IAM_CLIENT.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=getrolepolicy['Policy']['DefaultVersionId'])
        statements = getpolicyversion['PolicyVersion']['Document']['Statement']

        if are_statements_allow_logging(statements):
            return True

    return False

def are_statements_allow_logging(statements):

    is_createloggroup_present = False
    is_createlogstream_present = False
    is_putlogevents_present = False

    for statement in statements:
        if not is_effect_allow(statement) or not is_resource_element_ok(statement):
            continue

        if isinstance(statement['Action'], list):
            for action in statement['Action']:
                if action == "*" or action == "log:*":
                    return True
                elif action == "logs:CreateLogGroup":
                    is_createloggroup_present = True
                elif action == "logs:CreateLogStream":
                    is_createlogstream_present = True
                elif action == "logs:PutLogEvents":
                    is_putlogevents_present = True
        else:
            if statement['Action'] == "*" or statement['Action'] == "log:*":
                return True
            elif statement['Action'] == "logs:CreateLogGroup":
                is_createloggroup_present = True
            elif statement['Action'] == "logs:CreateLogStream":
                is_createlogstream_present = True
            elif statement['Action'] == "logs:PutLogEvents":
                is_putlogevents_present = True
    
    return is_createloggroup_present and is_createlogstream_present and is_putlogevents_present

def is_effect_allow(statement):
    return statement['Effect'] == "Allow"

def is_resource_element_ok(statement):
    if isinstance(statement['Resource'], list):
        for resource in statement['Resource']:
            if "arn:aws:logs" in resource or "*" in resource:
                return True
        return False
    return fnmatch.fnmatch(statement['Resource'], 'arn:aws:logs:*') or statement['Resource'] == "*"

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
    if not event:
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
def build_evaluation(resource_id, compliance_type, timestamp, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    eval = {}
    if annotation:
        eval['Annotation'] = annotation
    eval['ComplianceResourceType'] = resource_type
    eval['ComplianceResourceId'] = resource_id
    eval['ComplianceType'] = compliance_type
    eval['OrderingTimestamp'] = timestamp
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

# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT
    if ASSUME_ROLE_MODE:
        AWS_CONFIG_CLIENT = get_client('config', event)

    global IAM_CLIENT
    IAM_CLIENT = get_client('iam', event)

    evaluations = []

    #print(event)
    check_defined(event, 'event')
    invokingEvent = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    configuration_item = get_configuration_item(invokingEvent)

    if is_applicable(configuration_item, event):
        compliance_result = evaluate_compliance(configuration_item, rule_parameters)
    else:
        compliance_result = "NOT_APPLICABLE"

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
                evaluations.append(evaluation)
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
