# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
  IAM_IP_RESTRICTION

Description:
  To check IAM users are IP restricted.

Trigger:
  Periodic

Reports on:
  AWS::IAM::User

Rule Parameters:
  | ---------------------- | --------- | -------------------------------------------------------- |
  | Parameter Name         | Type      | Description                                              |
  | ---------------------- | --------- | -------------------------------------------------------- |
  | WhitelistedUserNames   | Optional  | Represents the IAM user names which are exempted from    |
  |                        |           | the IAM Config rule. The valid user names in this        |
  |                        |           | parameter will be compliant by default.                  |
  |                        |           | List of all the IAM user names separated by a comma.     |
  | ---------------------- | --------- | -------------------------------------------------------- |
  | maxIpNums              | Optional  | Numeric variable representing the maximum number of IP   |
  |                        |           | addresses that can be restricted. The default is 20.     |
  | ---------------------- | --------- | -------------------------------------------------------- |

Feature:
  In order to: enforce security best practices for IAM users
           As: a Security Officer
       I want: To ensure that IAM users are IP restricted, except if whitelisted

  Scenario: 1
    Given: No IAM Users
     Then: Return "NOT_APPLICABLE"

  Scenario: 2
    Given: WhitelistedUserNames is configured
      And: A user name in WhitelistedUserNames is greater than 64 characters
     Then: Return an error

  Scenario: 3
    Given: maxIpNums is configured
      And: maxIpNums is less than 0
     Then: Return an error

  Scenario: 4
    Given: An IAM user
      And: WhitelistedUserNames is configured and valid
      And: The IAM user is listed on the WhitelistedUserNames
     Then: Return COMPLIANT

  Scenario: 5
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is not IP allowed
      And: The IAM user  attached policy is     IP allowed
      And: The IAM group inline   policy is     IP allowed
      And: The IAM group attached policy is     IP allowed
     Then: return NON_COMPLIANT

  Scenario: 6
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is     IP allowed
      And: The IAM user  attached policy is not IP allowed
      And: The IAM group inline   policy is     IP allowed
      And: The IAM group attached policy is     IP allowed
     Then: return NON_COMPLIANT

  Scenario: 7
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is     IP allowed
      And: The IAM user  attached policy is     IP allowed
      And: The IAM group inline   policy is not IP allowed
      And: The IAM group attached policy is     IP allowed
     Then: return NON_COMPLIANT

  Scenario: 8
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is     IP allowed
      And: The IAM user  attached policy is     IP allowed
      And: The IAM group inline   policy is     IP allowed
      And: The IAM group attached policy is not IP allowed
     Then: return NON_COMPLIANT

  Scenario: 9
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is IP allowed
      And: The IAM user  attached policy is IP allowed
      And: The IAM group inline   policy is IP allowed
      And: The IAM group attached policy is IP allowed
     Then: return COMPLIANT

  Scenario: 10
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is     IP denied
      And: The IAM user  attached policy is not IP allowed
      And: The IAM group inline   policy is not IP allowed
      And: The IAM group attached policy is not IP allowed
     Then: return COMPLIANT

  Scenario: 11
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is not IP allowed
      And: The IAM user  attached policy is     IP denied
      And: The IAM group inline   policy is not IP allowed
      And: The IAM group attached policy is not IP allowed
     Then: return COMPLIANT

  Scenario: 12
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is not IP allowed
      And: The IAM user  attached policy is not IP allowed
      And: The IAM group inline   policy is     IP denied
      And: The IAM group attached policy is not IP allowed
     Then: return COMPLIANT

  Scenario: 13
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user  inline   policy is not IP allowed
      And: The IAM user  attached policy is not IP allowed
      And: The IAM group inline   policy is not IP allowed
      And: The IAM group attached policy is     IP denied
     Then: return COMPLIANT

  Scenario: 14
    Given: An IAM user
      And: The IAM user is not listed on the WhitelistedUserNames, if configured
      And: The IAM user inline policy is IP denied
      And: The number of set IP addresses are greater than maxIpNums
     Then: return NON_COMPLIANT
'''

import ipaddress
import json
import sys
import datetime
import boto3
import botocore

try:
    import liblogging
except ImportError:
    pass

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900
DEFAULT_MAX_IP_NUMS = 20

#############
# Main Code #
#############

def evaluate_compliance(event, _configuration_item, valid_rule_parameters):
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
    whitelisted_user_names = valid_rule_parameters['WhitelistedUserNames']
    max_ip_nums = valid_rule_parameters['maxIpNums']

    if not users_list:
        return None

    for user in users_list:
        if user['UserName'] in whitelisted_user_names:
            evaluations.append(build_evaluation(user['UserId'], 'COMPLIANT', event, annotation=f"This user {user['UserName']} is whitelisted."))
            continue

        evaluater = ComplianceEvaluater(iam_client, user['UserName'], max_ip_nums)
        compliance_type = evaluater.check_compliant()
        annotation = evaluater.annotation

        if compliance_type == 'NON_COMPLIANT' and annotation is None:
            annotation = f"This user {user['UserName']} is not IP restricted."

        evaluations.append(build_evaluation(user['UserId'], compliance_type, event, annotation=annotation))

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

def evaluate_parameters(rule_parameters):
    valid_rule_parameters = {}

    valid_rule_parameters['WhitelistedUserNames'] = []
    if 'WhitelistedUserNames' in rule_parameters:
        whitelisted_user_names = rule_parameters['WhitelistedUserNames'].replace(' ', '').split(',')
        valid_whitelist = []
        for whitelisted_user_name in whitelisted_user_names:
            if len(whitelisted_user_name) > 64:
                raise ValueError('WhitelistedUserNames must be less than 64 characters.')
            valid_whitelist.append(whitelisted_user_name)
        valid_rule_parameters['WhitelistedUserNames'] = valid_whitelist

    max_ip_nums = DEFAULT_MAX_IP_NUMS
    if 'maxIpNums' in rule_parameters:
        max_ip_nums = int(rule_parameters['maxIpNums'])
        if max_ip_nums < 1:
            raise ValueError('maxIpNums must be greater than 1.')
        if max_ip_nums > 2**32-1:
            raise ValueError('maxIpNums must be less than 2**32-1.')
    valid_rule_parameters['maxIpNums'] = max_ip_nums

    return valid_rule_parameters

class ComplianceEvaluater:
    # pylint: disable=R0902
    def __init__(self, iam_client, user_name, max_ip_num):
        self.__iam_client = iam_client
        self.__user_name = user_name
        self.__max_ip_num = max_ip_num
        self.__is_ip_denied = False
        self.__is_all_policy_ip_allowed = None
        self.__annotation = None

    @property
    def iam_client(self):
        return self.__iam_client

    @property
    def user_name(self):
        return self.__user_name

    @property
    def max_ip_num(self):
        return self.__max_ip_num

    @property
    def is_ip_denied(self):
        return self.__is_ip_denied

    @is_ip_denied.setter
    def is_ip_denied(self, value):
        self.__is_ip_denied = value

    @property
    def is_all_policy_ip_allowed(self):
        return self.__is_all_policy_ip_allowed

    @is_all_policy_ip_allowed.setter
    def is_all_policy_ip_allowed(self, value):
        self.__is_all_policy_ip_allowed = value

    @property
    def annotation(self):
        return self.__annotation

    @annotation.setter
    def annotation(self, value):
        self.__annotation = value

    def check_compliant(self):
        compliance_type = 'NON_COMPLIANT'

        self.__check_inline_policy()
        self.__check_attached_policy()

        user_groups = self.iam_client.list_groups_for_user(UserName=self.user_name)

        for group in user_groups['Groups']:
            group_name = group['GroupName']
            self.__check_group_inline_policy(group_name)
            self.__check_group_attached_policy(group_name)

        if self.is_ip_denied is True \
                or self.is_all_policy_ip_allowed is True:
            compliance_type = 'COMPLIANT'

        return compliance_type

    def __check_inline_policy(self):
        if self.is_ip_denied is True:
            return

        inline_policies = self.iam_client.list_user_policies(UserName=self.user_name)

        for inline_policy_name in inline_policies['PolicyNames']:
            inline_policy = self.iam_client.get_user_policy(
                UserName=self.user_name,
                PolicyName=inline_policy_name
            )
            statements = inline_policy['PolicyDocument']['Statement']
            self.__check_ip_restricted_condition(statements)

    def __check_attached_policy(self):
        if self.is_ip_denied is True:
            return

        attached_policies = self.iam_client.list_attached_user_policies(UserName=self.user_name)

        for attached_policy in attached_policies['AttachedPolicies']:
            policy_document = self.__get_policy_document(attached_policy['PolicyArn'], self.iam_client)
            statements = policy_document['Statement']
            self.__check_ip_restricted_condition(statements)

    def __check_group_inline_policy(self, group_name):
        if self.is_ip_denied is True:
            return

        group_inline_policies = self.iam_client.list_group_policies(GroupName=group_name)

        for group_inline_policy_name in group_inline_policies['PolicyNames']:
            group_inline_policy = self.iam_client.get_group_policy(
                GroupName=group_name,
                PolicyName=group_inline_policy_name
            )
            statements = group_inline_policy['PolicyDocument']['Statement']
            self.__check_ip_restricted_condition(statements)

    def __check_group_attached_policy(self, group_name):
        if self.is_ip_denied is True:
            return

        group_attached_policies = self.iam_client.list_attached_group_policies(GroupName=group_name)

        for group_attached_policy in group_attached_policies['AttachedPolicies']:
            policy_document = self.__get_policy_document(group_attached_policy['PolicyArn'], self.iam_client)
            statements = policy_document['Statement']
            self.__check_ip_restricted_condition(statements)

    @staticmethod
    def __get_policy_document(policy_arn, iam_client):
        policy = iam_client.get_policy(PolicyArn=policy_arn)
        policy_version_id = policy['Policy']['DefaultVersionId']
        policy_version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy_version_id
        )
        return policy_version['PolicyVersion']['Document']

    def __check_ip_restricted_condition(self, policy_statements):
        # Statements can be allow both list and dict, so in case of dict, convert to list
        if isinstance(policy_statements, dict):
            policy_statements = [policy_statements]

        for statement in policy_statements:
            if self.__is_ip_deny_condition_satisfied(statement):
                self.is_ip_denied = True
                break
            if self.__is_ip_allow_condition_satisfied(statement):
                if self.is_all_policy_ip_allowed is not False:
                    self.is_all_policy_ip_allowed = True
            else:
                self.is_all_policy_ip_allowed = False

    def __is_ip_deny_condition_satisfied(self, statement):
        try:
            allow_ips = []
            condition = statement['Condition']
            if statement['Effect'] == 'Deny':
                if 'NotIpAddress' in condition.keys():
                    allow_ips = condition['NotIpAddress']['aws:SourceIp']
                elif 'ForAnyValue:NotIpAddress' in condition.keys():
                    allow_ips = condition['ForAnyValue:NotIpAddress']['aws:SourceIp']
        except KeyError:
            pass

        return self.__is_valid_ips(allow_ips)

    def __is_ip_allow_condition_satisfied(self, statement):
        try:
            allow_ips = []
            condition = statement['Condition']
            if statement['Effect'] == 'Allow':
                if 'IpAddress' in condition.keys():
                    allow_ips = condition['IpAddress']['aws:SourceIp']
                elif 'ForAnyValue:IpAddress' in condition.keys():
                    allow_ips = condition['ForAnyValue:IpAddress']['aws:SourceIp']
        except KeyError:
            pass

        return self.__is_valid_ips(allow_ips)

    def __is_valid_ips(self, ips):
        if not ips:
            is_valid = False
        elif self.__is_over_maximum_ip_nums(ips):
            is_valid = False
        else:
            is_valid = True

        return is_valid

    def __is_over_maximum_ip_nums(self, ips):
        is_over = False
        unique_ips = list(set(ips))

        ip_nums = sum(ipaddress.ip_network(ip).num_addresses for ip in unique_ips)
        if ip_nums > self.max_ip_num:
            self.annotation = f'IAM Policy includes more than maximum ip addresses: {ip_nums}'
            is_over = True

        return is_over

####################
# Helper Functions #
####################

# Build an error to be displayed in the logs when the parameter is invalid.
def build_parameters_value_error_response(ex):
    """Return an error dictionary when the evaluate_parameters() raises a ValueError.

    Keyword arguments:
    ex -- Exception text
    """
    return  build_error_response(internal_error_message="Parameter value is invalid",
                                 internal_error_details="An ValueError was raised during the validation of the Parameter value",
                                 customer_error_code="InvalidParameterValueException",
                                 customer_error_message=str(ex))

# This gets the client after assuming the Config service role
# either in the same AWS account or cross-account.
def get_client(service, event, region=None):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    region -- the region where the client is called (default: None)
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service, region)
    credentials = get_assume_role_credentials(get_execution_role_arn(event), region)
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken'],
                        region_name=region
                       )

# This generate an evaluation for config
def build_evaluation(resource_id, compliance_type, event, resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    """Form an evaluation as a dictionary. Usually suited to report on scheduled rules.

    Keyword arguments:
    resource_id -- the unique id of the resource to report
    compliance_type -- either COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
    event -- the event variable given in the lambda handler
    resource_type -- the CloudFormation resource type (or AWS::::Account) to report on the rule (default DEFAULT_RESOURCE_TYPE)
    annotation -- an annotation to be added to the evaluation (default None). It will be truncated to 255 if longer.
    """
    eval_cc = {}
    if annotation:
        eval_cc['Annotation'] = build_annotation(annotation)
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
    annotation -- an annotation to be added to the evaluation (default None). It will be truncated to 255 if longer.
    """
    eval_ci = {}
    if annotation:
        eval_ci['Annotation'] = build_annotation(annotation)
    eval_ci['ComplianceResourceType'] = configuration_item['resourceType']
    eval_ci['ComplianceResourceId'] = configuration_item['resourceId']
    eval_ci['ComplianceType'] = compliance_type
    eval_ci['OrderingTimestamp'] = configuration_item['configurationItemCaptureTime']
    return eval_ci

####################
# Boilerplate Code #
####################

# Get execution role for Lambda function
def get_execution_role_arn(event):
    role_arn = None
    if 'ruleParameters' in event:
        rule_params = json.loads(event['ruleParameters'])
        role_name = rule_params.get("ExecutionRoleName")
        if role_name:
            execution_role_prefix = event["executionRoleArn"].split("/")[0]
            role_arn = "{}/{}".format(execution_role_prefix, role_name)

    if not role_arn:
        role_arn = event['executionRoleArn']

    return role_arn

# Build annotation within Service constraints
def build_annotation(annotation_string):
    if len(annotation_string) > 256:
        return annotation_string[:244] + " [truncated]"
    return annotation_string

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
    configuration_item = result['configurationItems'][0]
    return convert_api_configuration(configuration_item)

# Convert from the API model to the original invocation model
def convert_api_configuration(configuration_item):
    for k, v in configuration_item.items():
        if isinstance(v, datetime.datetime):
            configuration_item[k] = str(v)
    configuration_item['awsAccountId'] = configuration_item['accountId']
    configuration_item['ARN'] = configuration_item['arn']
    configuration_item['configurationStateMd5Hash'] = configuration_item['configurationItemMD5Hash']
    configuration_item['configurationItemVersion'] = configuration_item['version']
    configuration_item['configuration'] = json.loads(configuration_item['configuration'])
    if 'relationships' in configuration_item:
        for i in range(len(configuration_item['relationships'])):
            configuration_item['relationships'][i]['name'] = configuration_item['relationships'][i]['relationshipName']
    return configuration_item

# Based on the type of message get the configuration item
# either from configurationItem in the invoking event
# or using the getResourceConfigHistiry API in getConfiguration function.
def get_configuration_item(invoking_event):
    check_defined(invoking_event, 'invokingEvent')
    if is_oversized_changed_notification(invoking_event['messageType']):
        configuration_item_summary = check_defined(invoking_event['configurationItemSummary'], 'configurationItemSummary')
        return get_configuration(configuration_item_summary['resourceType'], configuration_item_summary['resourceId'], configuration_item_summary['configurationItemCaptureTime'])
    if is_scheduled_notification(invoking_event['messageType']):
        return None
    return check_defined(invoking_event['configurationItem'], 'configurationItem')

# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configuration_item, event):
    try:
        check_defined(configuration_item, 'configurationItem')
        check_defined(event, 'event')
    except:
        return True
    status = configuration_item['configurationItemStatus']
    event_left_scope = event['eventLeftScope']
    if status == 'ResourceDeleted':
        print("Resource Deleted, setting Compliance Status to NOT_APPLICABLE.")

    return status in ('OK', 'ResourceDiscovered') and not event_left_scope


def get_assume_role_credentials(role_arn, region=None):
    sts_client = boto3.client('sts', region)
    try:
        assume_role_response = sts_client.assume_role(RoleArn=role_arn,
                                                      RoleSessionName="configLambdaExecution",
                                                      DurationSeconds=CONFIG_ROLE_TIMEOUT_SECONDS)
        if 'liblogging' in sys.modules:
            liblogging.logSession(role_arn, assume_role_response)
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

def lambda_handler(event, _context):
    if 'liblogging' in sys.modules:
        liblogging.logEvent(event)

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
    result_token = event['resultToken']
    test_mode = False
    if result_token == 'TESTMODE':
        # Used solely for RDK test to skip actual put_evaluation API call
        test_mode = True

    # Invoke the Config API to report the result of the evaluation
    evaluation_copy = []
    evaluation_copy = evaluations[:]
    while evaluation_copy:
        AWS_CONFIG_CLIENT.put_evaluations(Evaluations=evaluation_copy[:100], ResultToken=result_token, TestMode=test_mode)
        del evaluation_copy[:100]

    # Used solely for RDK test to be able to test Lambda function
    return evaluations

def is_internal_error(exception):
    return ((not isinstance(exception, botocore.exceptions.ClientError)) or exception.response['Error']['Code'].startswith('5')
            or 'InternalError' in exception.response['Error']['Code'] or 'ServiceError' in exception.response['Error']['Code'])

def build_internal_error_response(internal_error_message, internal_error_details=None):
    return build_error_response(internal_error_message, internal_error_details, 'InternalError', 'InternalError')

def build_error_response(internal_error_message, internal_error_details=None, customer_error_code=None, customer_error_message=None):
    error_response = {
        'internalErrorMessage': internal_error_message,
        'internalErrorDetails': internal_error_details,
        'customerErrorMessage': customer_error_message,
        'customerErrorCode': customer_error_code
    }
    print(error_response)
    return error_response
