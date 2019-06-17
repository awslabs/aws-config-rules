# Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
'''
#####################################
##           Gherkin               ##
#####################################

Rule Name:
  VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS

Description:
  Checks that the security group with 0.0.0.0/0 of any VPCs allows only certain TCP or UDP traffic (Inbound only). If no ports are provided in the parameters, any security group with inbound 0.0.0.0/0 will be NON_COMPLIANT.

Trigger:
  Configuration Changes on AWS::EC2::SecurityGroup

Reports on:
  AWS::EC2::SecurityGroup

Rule Parameters:
  authorizedTcpPorts (Optional)
       List of TCP ports authorized to be open to 0.0.0.0/0, separated by comma. Ranges can be defined by dash. Ex: "443,1020-1025"
  authorizedUdpPorts (Optional)
       List of UDP ports authorized to be open to 0.0.0.0/0, separated by comma. Ranges can be defined by dash. Ex: "500,1020-1025"

Scenarios:
  Scenario: 1_evalparam_tcpnotvalid_error
    Given: authorizedTcpPorts is configured and not valid
	 Then: Return Error

  Scenario: 2_evalparam_udppnotvalid_error
    Given: authorizedUdpPorts is configured and not valid
	 Then: Return Error

  Scenario: 3_evalcompliance_notopen_notapplicable
	Given: The Security Group has no inbound port open to '0.0.0.0/0'
	 Then: Return NOT_APPLICABLE

  Scenario: 4_evalcompliance_updopennotauthorized_noncompliant
	Given: The Security Group has at least 1 UDP inbound port open to '0.0.0.0/0'
	  And: Open UDP ports not in authorizedUdpPorts
	 Then: Return NON_COMPLIANT

  Scenario: 5_evalcompliance_tcpopennotauthorized_noncompliant
	Given: The Security Group has at least 1 TCP inbound port open to '0.0.0.0/0'
	  And: Open TCP ports not in authorizedTcpPorts
	 Then: Return NON_COMPLIANT

  Scenario: 6_evalcompliance_tcpnotopen_udpauthorized_compliant
	Given: The Security Group has at least 1 UDP inbound port open to '0.0.0.0/0'
	  And: No TCP ports are open to '0.0.0.0/0'
	  And: Open UDP ports in authorizedUdpPorts
	 Then: Return COMPLIANT

  Scenario: 7_evalcompliance_udpnotopen_tcpauthorized_compliant
	Given: The Security Group has at least 1 TCP inbound port open to '0.0.0.0/0'
	  And: No UDP ports are open to '0.0.0.0/0'
	  And: Open TCP ports in authorizedTcpPorts
	 Then: Return COMPLIANT

  Scenario: 8_evalcompliance_udpauthorized_tcpauthorized_compliant
	Given: The Security Group has at least 1 TCP inbound port open to '0.0.0.0/0'
	  And: The Security Group has at least 1 UDP inbound port open to '0.0.0.0/0'
	  And: Open TCP ports in authorizedTcpPorts
	  And: Open UDP ports in authorizedUdpPorts
	 Then: Return COMPLIANT
 '''

import json
import datetime
import boto3
import botocore
import re

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::SecurityGroup'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

#############
# Main Code #
#############

def evaluate_compliance(event, configuration_item, valid_rule_parameters):
    is_any_open_allowed = False
    
    for rule in configuration_item['configuration']['ipPermissions']:
        rule_range = PortRange(rule.get('fromPort', 0), rule.get('toPort', 65535))
        for ip_range in rule['ipv4Ranges']:
            if not ip_range['cidrIp'] == '0.0.0.0/0':
                continue

            is_any_open_allowed = True
            protocol = rule['ipProtocol']

            if protocol in ['udp', '-1']:
                non_compliant_annotation = get_non_compliant_annotation('UDP', 'authorizedUdpPorts', valid_rule_parameters, rule_range)
                if non_compliant_annotation:
                    return build_evaluation_from_config_item(configuration_item, 'NON_COMPLIANT', annotation=non_compliant_annotation)

            if protocol in ['tcp', '-1']:
                non_compliant_annotation = get_non_compliant_annotation('TCP', 'authorizedTcpPorts', valid_rule_parameters, rule_range)
                if non_compliant_annotation:
                    return build_evaluation_from_config_item(configuration_item, 'NON_COMPLIANT', annotation=non_compliant_annotation)

    if is_any_open_allowed:
        return build_evaluation_from_config_item(configuration_item, 'COMPLIANT')
    return build_evaluation_from_config_item(configuration_item, 'NOT_APPLICABLE')

def evaluate_parameters(rule_parameters):
    valid_rule_parameters = {}
    if 'authorizedTcpPorts' in rule_parameters:
        valid_rule_parameters['authorizedTcpPorts'] = evaluate_port(rule_parameters['authorizedTcpPorts'])
    if 'authorizedUdpPorts' in rule_parameters:
        valid_rule_parameters['authorizedUdpPorts'] = evaluate_port(rule_parameters['authorizedUdpPorts'])
    return valid_rule_parameters

def get_non_compliant_annotation(protocol, parameter_name, valid_rule_parameters, rule_range):
    if not parameter_name in valid_rule_parameters:
        return 'No {} port is authorized to be open, according to the {} parameter.'.format(protocol, parameter_name)
    authorized_ports = valid_rule_parameters[parameter_name]
    if not rule_range.included_in_one_of_the_ranges(authorized_ports):
        return 'One or more {} ports ({}) are not in range of the {} parameter ({}).'.format(protocol, rule_range.get_str(), parameter_name, get_str_range_list(authorized_ports))
    return None

class PortRange:
    begin = None
    end = None
    def __init__(self, from_port=None, to_port=None):
        if not to_port:
            to_port = from_port
        self.begin = from_port
        self.end = to_port

    def get_str(self):
        if self.begin == self.end:
            return str(self.begin)
        return '{}-{}'.format(self.begin, self.end)

    def included_in_one_of_the_ranges(self, range_list):
        for port_range in range_list:
            if port_range.begin <= self.begin <= port_range.end and port_range.begin <= self.end <= port_range.end:
                return True
        return False

def get_str_range_list(range_list):
    range_str = ''
    for range_obj in range_list:
        if not range_str:
            range_str = range_obj.get_str()
        else:
            range_str += ','
            range_str += range_obj.get_str()
    return range_str

def evaluate_port(ports_string):
    port_list = [each_port.strip() for each_port in ports_string.split(',')]

    return_list = []
    for port in port_list:
        entry = PortRange()
        if '-' in port:
            indiv_ports = port.split('-')
            if len(indiv_ports) > 2:
                raise ValueError('Port ranges must have only 1 dash. Please review "{}".'.format(port))
            try:
                entry.begin = int(indiv_ports[0].strip())
                entry.end = int(indiv_ports[1].strip())
            except:
                raise ValueError('Ports must be between 0 and 65535.')
        else:
            try:
                entry.begin = int(port)
                entry.end = int(port)
            except:
                raise ValueError('Ports must be between 0 and 65535.')
        if entry.begin > entry.end:
            raise ValueError('Ports must be in order for ranges.')
        if entry.begin < 0 or entry.begin > 65535 or entry.end < 0 or entry.end > 65535:
            raise ValueError('Ports must be between 0 and 65535.')
        return_list.append(entry)
    return return_list

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.

    Keyword arguments:
    ex -- Exception text
    """
    return  build_error_response(internalErrorMessage="Parameter value is invalid",
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
