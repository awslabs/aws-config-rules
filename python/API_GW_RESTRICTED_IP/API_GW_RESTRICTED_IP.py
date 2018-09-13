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
  api-gw-restricted-to-ip

Description:
  Verify that non-private API GW have a resource based policy which limit their usage based on IP source (configurable)

Trigger:
  Periodic

Reports on:
  AWS::ApiGateway::RestApi

Parameters:
  | --------------------|-----------|-----------------------------------------------|-------------------------|
  | Parameter Name      | Type      | Description                                   | Notes                   |
  | ------------------- | --------- | --------------------------------------------- |-------------------------|
  | WhitelistedIPs      | Mandatory | IP addresses whitelisted to invoke the rest   | Seperated by comma (,)  |
  |                     |           | API.                                          |                         |
  |---------------------|-----------|-----------------------------------------------|-------------------------| 

Feature:
    In order to: to limit the access to API
             As: a Security Officer
         I want: To ensure that non-private REST APIs in API GW have a resource based policy which limit their usage based on whitelisted IPs.

Scenarios:
	Scenario 1:
	  Given: WhitelistedIPs parameter is not defined
	   Then: return Error

	Scenario 2:
	  Given: WhitelistedIPs parameter has an incorrect value (empty, non-CIDR, list of non-CIDR)
	   Then: return Error

    Scenario 3:
	  Given: API is in private mode
	   Then: return NOT_APPLICABLE

    Scenario 3:
	  Given: WhitelistedIPs parameter is defined and valid
        And: APIs do not have resource policy attached
	   Then: return NON_COMPLIANT
    
    Scenario 4:
	  Given: WhitelistedIPs parameter is defined and valid
        And: APIs have resource policy attached
        And: The Resource policy does not contain any 'Allow' statement
	   Then: return COMPLIANT

	Scenario 5:
	  Given: WhitelistedIPs parameter is defined and valid
        And: APIs have resource policy attached
	    And: The Resource policy does not contain <Options of Policy> 
	   Then: return NON_COMPLIANT

    With:    
        | Options of Policy                                      |
        | any 'Condition'                                        |
        | any 'Condition' about 'IpAddress'                      |
        | any 'Condition' about 'IpAddress' about 'aws:SourceIp' |

	Scenario 6:
	  Given: WhitelistedIPs parameter is defined and valid
        And: APIs have resource policy attached
	    And: The Resource policy contains a 'Condition' about 'IpAddress' about 'aws:SourceIp'
	    And: Those IPs are not a subset of the WhitelistedIPs
	   Then: return NON_COMPLIANT

	Scenario 7:
	  Given: WhitelistedIPs parameter is defined and valid
        And: APIs have resource policy attached
	    And: The Resource policy contains a 'Condition' about 'IpAddress' about 'aws:SourceIp'
	    And: Those IPs are a subset of the WhitelistedIPs
	   Then: return COMPLIANT

'''

import json
import datetime
import ipaddress
import boto3
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::RestApi'

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
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    
    Advanced Notes:
    1 -- the deleted resources are taken care of by the Boilerplate code
    2 -- if a list of dictionary is returned, the old evaluation(s) which are not returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
    3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a "shadow" evaluation to feedback that the evaluation took place properly
    """

    apigw_client = get_client('apigateway', event)
    gateways_list = get_all_api_gateway(apigw_client)
    
    if not gateways_list:
        return None
    
    evaluations = []
    for gateway in gateways_list:

        if gateway['endpointConfiguration']['types'] == ['PRIVATE']:
            evaluations.append(build_evaluation(gateway['name'], 'NOT_APPLICABLE', event))
            continue
        
        
        if 'policy' not in gateway:
            evaluations.append(build_evaluation(gateway['name'], 'NON_COMPLIANT', event, annotation='No resource policy is attached.'))
            continue

        policy = json.loads(gateway['policy'].replace('\\',''))
        
        if is_policy_allows_more_than_whitelist(policy, rule_parameters):
            evaluations.append(build_evaluation(gateway['name'], 'NON_COMPLIANT', event, annotation='The attached policy allows more than the whitelist.'))
            continue
        
        evaluations.append(build_evaluation(gateway['name'], 'COMPLIANT', event))

    return evaluations

def is_policy_allows_more_than_whitelist(policy, whitelist):
    for statement in policy['Statement']:
        if statement['Effect'] != 'Allow':
            continue
        
        if 'Condition' not in statement:
            return True
        
        if 'IpAddress' not in statement['Condition']:
            return True

        if 'aws:SourceIp' not in statement['Condition']['IpAddress']:
            return True
      
        if not is_ip_in_whitelist(statement['Condition']['IpAddress']['aws:SourceIp'], whitelist):
            return True

    return False

def is_ip_in_whitelist(ip_list_or_str, whitelist):

    all_network_in_ip_list = get_all_ip_networks(ip_list_or_str)
    all_network_in_whitelist = get_all_ip_networks(whitelist)
    
    for net in all_network_in_ip_list:
        is_network_included = False
        for net_whitelisted in  all_network_in_whitelist:
            try:
                list(net_whitelisted.address_exclude(net))
                is_network_included = True
            except:
                continue
        if not is_network_included:
            return False
    return True

def get_all_ip_networks(ip_list_or_str):                
    ip_network_to_return = []
    if isinstance(ip_list_or_str, str):
        ip_network_to_return.append(ipaddress.ip_network(ip_list_or_str, strict=False))
    elif isinstance(ip_list_or_str, list):
        for addr in ip_list_or_str:
            ip_network_to_return.append(ipaddress.ip_network(addr, strict=False))
    else:
        raise ValueError("Unexpected value in the aws:SourceIp field of the policy.")
    return ip_network_to_return
        
def get_all_api_gateway(client):
    rest_apis_list = client.get_rest_apis(limit=500)
    apis_list = []
    while True:
        for item in rest_apis_list['items']:
            apis_list.append(item)
        if 'position' in rest_apis_list:
            next_position = rest_apis_list['position']
            rest_apis_list = client.get_rest_apis(position=next_position,limit=500)
        else:
            break
    return apis_list

def evaluate_parameters(rule_parameters):
    if 'WhitelistedIPs' not in rule_parameters:
        raise ValueError('The parameter with "WhitelistedIPs" as key must be defined.')
    if not rule_parameters['WhitelistedIPs']:
        raise ValueError('The parameter "WhitelistedIPs" must have a defined value.')
    try:
        cleaned_parameters = rule_parameters['WhitelistedIPs'].replace(', ',',').split(',')
    except:
        raise ValueError('The parameter "WhitelistedIPs" must be a string or a list of strings separated by comma.')
    for addr in cleaned_parameters:
        if not is_ip_address(addr) and not is_ip_network(addr):
            raise ValueError('The value in parameter "WhitelistedIPs" [' + str(addr) + '] is not a valid IP or a valid IP network.')
    return cleaned_parameters

def is_ip_address(addr):
    try:
        ipaddress.ip_address(addr)
        return True
    except:
        return False

def is_ip_network(net):
    try:
        ipaddress.ip_network(net, strict=False)
        return True
    except:
        return False

def build_parameters_value_error_response(ex):
    return  build_error_response(internalErrorMessage="Customer error while parsing input parameters",
                                 internalErrorDetails="Parameter value is invalid",
                                 customerErrorCode="InvalidParameterValueException",
                                 customerErrorMessage=str(ex))

####################
# Helper Functions #
####################

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

# Helper function to check if rule parameters exist
def parameters_exist(parameters):
    return len(parameters) != 0

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
        if 'AccessDenied' in ex.response['Error']['Code']:
            ex.response['Error']['Message'] = "AWS Config does not have permission to assume the IAM role."
        else:
            ex.response['Error']['Message'] = "InternalError"
            ex.response['Error']['Code'] = "InternalError"
        raise ex

# This removes older evaluation (usually useful for periodic rule not reporting on AWS::::Account).
def clean_up_old_evaluations(latest_evaluations, event):

    cleaned_evalations = []

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
            cleaned_evalations.append(build_evaluation(old_resource_id, "NOT_APPLICABLE", event))

    return cleaned_evalations + latest_evaluations

# This decorates the lambda_handler in rule_code with the actual PutEvaluation call
def lambda_handler(event, context):

    global AWS_CONFIG_CLIENT
    AWS_CONFIG_CLIENT = get_client('config', event)

    #print(event)
    check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    try:
        rule_parameters_clean = evaluate_parameters(rule_parameters)
    except ValueError as ex:
        return build_parameters_value_error_response(ex)

    try:
        configuration_item = get_configuration_item(invoking_event)
        if invoking_event['messageType'] in ['ConfigurationItemChangeNotification', 'ScheduledNotification', 'OversizedConfigurationItemChangeNotification']:
            if is_applicable(configuration_item, event):
                compliance_result = evaluate_compliance(event, configuration_item, rule_parameters_clean)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return {'internalErrorMessage': 'Unexpected message type ' + str(invoking_event)}
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
