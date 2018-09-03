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
	VPC_DEFAULT_SECURITY_GROUP_BLOCKED

Description:
	Checks that the default security group of any VPCs does not allow any traffic (Inbound and Outbound)

Trigger:
    AWS::EC2::SecurityGroup

Rule Parameters:
    None

Feature:
	In order to: enforce our Security Policies
	         As: a Security Officer
	     I want: to ensure that default security group of any VPCs does not allow any traffic

Scenarios:
  Scenario 1:
	Given: The Security Group is not a default SG
	 Then: Return NOT_APPLICABLE

  Scenario 2:
	Given: The Security Group is a default SG
	  And: At least one Inbound rule or Outbound rule is present in the default SG
	 Then: Return NON_COMPLIANT

  Scenario 3:
    Given: The Security Group is a default SG
      And: No Inbound and no Outbound rule is present
     Then: Return COMPLIANT
'''

import json
import datetime
import boto3
import botocore

AWS_CONFIG_CLIENT = boto3.client('config')

DEFAULT_RESOURCE_TYPE = "AWS::EC2::SecurityGroup"
ASSUME_ROLE_MODE = False

def evaluate_compliance(configuration_item, rule_parameters):

    if configuration_item['configuration']['groupName'] != 'default':
        return 'NOT_APPLICABLE'

    if configuration_item['configuration']['ipPermissions']:
        return build_evaluation_from_config_item(
            configuration_item,
            'NON_COMPLIANT',
            annotation="This default Security Group has one or more Ingress rules.")

    if configuration_item['configuration']['ipPermissionsEgress']:
        return build_evaluation_from_config_item(
            configuration_item,
            'NON_COMPLIANT',
            annotation="This default Security Group has one or more Egress rules.")

    return 'COMPLIANT'


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
        return get_configuration(configurationItemSummary['resourceType'], configurationItemSummary['resourceId'],
                                 configurationItemSummary['configurationItemCaptureTime'])
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

    evaluations = []

    # print(event)
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
