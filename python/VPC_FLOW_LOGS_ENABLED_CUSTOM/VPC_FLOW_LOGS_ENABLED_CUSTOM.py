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
    vpc-flow-logs-enabled

Description: 
    Check whether VPCs have Flow Logs enabled.

Trigger: 
    Periodic

Reports on: 
    AWS::EC2::VPC

Rule Parameters:

+------------------+----------------+--------------------------------------------------------------------------------------------+
|   Parameter Name | Type           |                                          Description                                       |
+------------------+----------------+--------------------------------------------------------------------------------------------+
| WhiteListedVPC   | Optional       | This parameter can be used to white-list VPCs, the white-listed VPCs will not be evaluated |
|                  |                | and be returned as COMPLIANT. Separate multiple VPCs by a comma.                           |
+------------------+----------------+--------------------------------------------------------------------------------------------+
| LogGroupName     | Optional       | This parameter specifies the logGroupName where the flow logs must be sent to.             |
|                  |                |                                                                                            |
+------------------+----------------+--------------------------------------------------------------------------------------------+
| TrafficType      | Optional       | This parameter defines the type of traffic that is being logged for a VPC. By default,     |
|                  |                | the rule checks for 'ALL'. Possible values are ALL, ACCEPT & REJECT                        |
+------------------+----------------+--------------------------------------------------------------------------------------------+

Feature:
  In order to: monitor traffic for a VPC
           As: a Security Officer
       I want: to ensure that all VPCs have Flow logs associated as per requirements.

Scenarios:

  Scenario 1:
    Given: The parameter WhiteListedVPC or TrafficType or LogGroupName is not valid
     Then: Raise Exception

  Scenario 2:
    Given: The parameter WhiteListedVPC is configured and valid
      And: The VPC is in the WhiteListedVPC list
     Then: Return COMPLIANT

  Scenario 3:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The VPC does not have any Flow Logs associated
     Then: Return NON_COMPLIANT

  Scenario 4:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The VPC have no Flow Logs associated with a SUCCESS deliver-log-status
     Then: Return NON_COMPLIANT
  
  Scenario 5:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is not configured
      And: The parameter LogGroupName is not configured
      And: The VPC has no Flow Logs associated with TrafficType set to ALL
     Then: Return NON_COMPLIANT

  Scenario 6:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is not configured
      And: The parameter LogGroupName is not configured
      And: The VPC has a Flow Logs associated with TrafficType set to ALL 
     Then: Return COMPLIANT
  
  Scenario 7:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is not configured
      And: The parameter LogGroupName is configured and valid
      And: The VPC has no Flow Logs associated with TrafficType set to ALL and the LogGroupName matches the parameter LogGroupName
     Then: Return NON_COMPLIANT
  
  Scenario 8:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is not configured
      And: The parameter LogGroupName is configured and valid
      And: The VPC has a Flow Logs associated with TrafficType set to ALL and the LogGroupName matches the parameter LogGroupName
     Then: Return COMPLIANT

  Scenario 9:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is configured and valid
      And: The VPC has no Flow Logs associated with TrafficType matching the parameter TrafficType
     Then: Return NON_COMPLIANT

  Scenario 10:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is configured and valid
      And: The parameter LogGroupName is configured and valid
      And: The VPC has no Flow Logs associated with TrafficType matching the parameter TrafficType and the LogGroupName matches the parameter LogGroupName
     Then: Return NON_COMPLIANT

  Scenario 11:
    Given: The parameter WhiteListedVPC is neither configured nor matching the VPC
      And: The parameter TrafficType is configured and valid
      And: The parameter LogGroupName is configured and valid
      And: The VPC has a Flow Logs associated with TrafficType matching the parameter TrafficType and the LogGroupName matches the parameter LogGroupName
     Then: Return COMPLIANT
'''

import json
import datetime
import boto3
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::VPC'

# List of the parameter allowed for the Rule
ALLOWED_PARAMETER_NAMES = ['WhiteListedVPC', 'TrafficType', 'LogGroupName']

# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False

#############
# Main Code #
#############

def evaluate_compliance(event, configuration_item, rule_parameters):
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

    evaluations = []
    
    ec2_client = get_client('ec2', event)
    vpc_id_list = get_all_vpc_id(ec2_client)
    vpc_flow_log_list = get_all_flow_logs(ec2_client, vpc_id_list)
    print(vpc_flow_log_list)

    for vpc_id in vpc_id_list:
        if rule_parameters['WhiteListedVPC']:
            if vpc_id in rule_parameters['WhiteListedVPC']:
                evaluations.append(build_evaluation(vpc_id, 'COMPLIANT', event, annotation='This is a WhiteListed VPC.'))
                continue

        flow_log_exist = False
        flow_log_no_error = False
        traffic_type_matched = False
        log_group_correct = False

        for vpc_flow_log in vpc_flow_log_list:
            if vpc_flow_log['ResourceId'] != vpc_id:
                continue    
            flow_log_exist = True
            
            if vpc_flow_log['TrafficType'] != rule_parameters['TrafficType']:
                continue
            traffic_type_matched = True
        
            if rule_parameters['LogGroupName']:
                if rule_parameters['LogGroupName'] != vpc_flow_log['LogGroupName']:
                    continue
            log_group_correct = True
            
            if 'DeliverLogsErrorMessage' in vpc_flow_log:
                delivery_error_msg = vpc_flow_log['DeliverLogsErrorMessage']
                continue
            flow_log_no_error = True

        if not flow_log_exist:
            evaluations.append(build_evaluation(vpc_id, 'NON_COMPLIANT', event, annotation='No flow log has been configured.'))
            continue

        if not traffic_type_matched:
            evaluations.append(build_evaluation(vpc_id, 'NON_COMPLIANT', event, annotation='No flow log matches with the traffic type {0}.'.format(rule_parameters['TrafficType'])))
            continue

        if not log_group_correct:
            evaluations.append(build_evaluation(vpc_id, 'NON_COMPLIANT', event, annotation='No flow log matches with the log group name {0}.'.format(rule_parameters['LogGroupName'])))
            continue
        
        if not flow_log_no_error:
            evaluations.append(build_evaluation(vpc_id, 'NON_COMPLIANT', event, annotation='The following error occured in the flow log delivery: {0}.'.format(delivery_error_msg)))
            continue

        evaluations.append(build_evaluation(vpc_id, 'COMPLIANT', event))

    return evaluations

def get_all_flow_logs(ec2_client, vpc_list):
    flow_logs = ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': vpc_list}], MaxResults=1000)
    all_flow_logs = []
    while True:
        all_flow_logs += flow_logs['FlowLogs']
        if "NextToken" in flow_logs:
                flow_logs = ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': vpc_list}], NextToken=flow_logs["NextToken"], MaxResults=1000)
        else:
            break
    return all_flow_logs

def get_all_vpc_id(ec2_client):
    vpc_list = ec2_client.describe_vpcs()['Vpcs']
    vpc_id_list = []
    for vpc in vpc_list:
        vpc_id_list.append(vpc['VpcId'])
    return vpc_id_list    

def evaluate_parameters(rule_parameters):
    """Evaluate the rule parameters dictionary validity. Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """

    for key in rule_parameters:
        if key not in ALLOWED_PARAMETER_NAMES:
            raise ValueError('The parameter ' + key + ' is not a valid parameter key.')

    validated_rule_parameters = {}

    validated_rule_parameters['WhiteListedVPC'] = []
    if 'WhiteListedVPC' in rule_parameters:
        whitelisted_vpcs = rule_parameters['WhiteListedVPC'].replace(' ', '').split(',')
        for vpc in whitelisted_vpcs:
            if not vpc.startswith('vpc-'):
                raise ValueError('The parameter "WhiteListedVPC" is not a valid vpc-id format.')
        validated_rule_parameters['WhiteListedVPC'] = whitelisted_vpcs

    validated_rule_parameters['TrafficType'] = 'ALL'
    if 'TrafficType' in rule_parameters:
        if rule_parameters['TrafficType'] not in ['ACCEPT', 'REJECT', 'ALL']:
            raise ValueError('The parameter "TrafficType" must be ALL, ACCEPT or REJECT.')  
        validated_rule_parameters['TrafficType'] = rule_parameters['TrafficType']

    validated_rule_parameters['LogGroupName'] = None
    if 'LogGroupName' in rule_parameters:
        validated_rule_parameters['LogGroupName'] = rule_parameters['LogGroupName']

    return validated_rule_parameters

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
