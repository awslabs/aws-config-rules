"""
#####################################
##           Gherkin               ##
#####################################

Rule Name:
    AMI_OUTDATED_CHECK

Description:
    Check all private AMIs are not older than X days.

Trigger:
    Periodic

Resource Type to report on:
    AWS::EC2::Instance

Rule Parameters:
    | -------------------- | --------- | --------------------------------------------- | ------------------|
    | Parameter Name       | Type      | Description                                   |     Notes         |
    | -------------------- | --------- | --------------------------------------------- | ------------------|
    | NumberOfDays         | Optional  | The number of days against which the ami age  | must be equal to  |
    |                      |           | of the instances will be compared.            | or less than      |
    |                      |           | Default value: 90 days                        |                   |
    | -------------------- | --------- | --------------------------------------------- | ------------------|
    | WhitelistedAmis      | Optional  | The list of AMI Ids provided by the user to   | must be equal to  |
    |                      |           | be excluded from the check.                   | item in list.     |
    | -------------------- | --------- | --------------------------------------------- | ----------------- |
    | WhitelistedInstances | Optional  | The list of Instance ID's provided by the     | must be equal to  |
    |                      |           | user to be excluded from the check.           | item in list.     |
    |--------------------- |-----------|-----------------------------------------------|-------------------|

Feature:
    In order to: to use latest AMI
             As: a Security Officer
         I want: To ensure that all AMIs of the account is not older than X number of days.

Scenarios:
  Scenario 1:
  Given: NumberOfDays, WhitelistedAmis or WhitelistedInstances parameters are not present
   Then: Return value error

  Scenario 2:
  Given: NumberOfDays parameter is configured
    And: NumberOfDays parameter is not an integer
   Then: Return value error

  Scenario 3:
  Given: NumberOfDays parameter is configured
    And: NumberOfDays parameter is less than 1
   Then: Return value error

  Scenario 4:
  Given: NumberOfDays parameter is valid
    And: WhitelistedAmis parameter is configured
    And: The format of a WhitelistedAmis parameter element does not match the AMI ID format
   Then: Return value error

  Scenario 5:
  Given: NumberOfDays parameter is valid
    And: WhitelistedAmis parameter is valid
    And: WhitelistedInstances parameter is configured
    And: The format of a WhitelistedInstances parameter item does not match the Instance ID format
   Then: Return value error

  Scenario 6:
  Given: NumberOfDays parameter has not been configured
    And: WhitelistedAmis parameter is valid
    And: WhitelistedInstances parameter is valid
    And: The Instance AMI age is less than or equal to default value (90 days)
   Then: Return COMPLIANT

  Scenario 7:
  Given: NumberOfDays parameter has not been configured
    And: WhitelistedAmis parameter is valid
    And: Instance AMI ID is not contained in the WhitelistedAmis parameter
    And: WhitelistedInstances parameter is valid
    And: Instance ID is not contained in the WhitelistedInstances parameter
    And: The Instance AMI age is greater than default value (90 days)
   Then: Return NON_COMPLIANT

  Scenario 8:
  Given: NumberOfDays parameter has been configured
    And: NumberOfDays parameter is valid
    And: WhitelistedAmis parameter is valid
    And: Instance AMI ID is not contained in the WhitelistedAmis parameter
    And: WhitelistedInstances parameter is valid
    And: Instance ID is not contained in the WhitelistedInstances parameter
    And: The Instance AMI age is greater than configured value
   Then: Return NON_COMPLIANT

  Scenario 9:
  Given: NumberOfDays parameter has been configured
    And: NumberOfDays parameter is valid
    And: WhitelistedAmis parameter is valid
    And: WhitelistedInstances parameter is valid
    And: The Instance AMI age is less than or equal to than configured value
   Then: Return COMPLIANT

  Scenario 10:
  Given: NumberOfDays parameter is valid
    And: WhitelistedAmis parameter is valid
    And: WhitelistedInstances parameter is valid
    And: The Instance AMI ID is contained in the WhitelistedAmis parameter
   Then: Return COMPLIANT

  Scenario 11:
  Given: NumberOfDays parameter is valid
    And: WhitelistedAmis parameter is valid
    And: WhitelistedInstances parameter is valid
    And: The Instance ID is contained in the WhitelistedInstances parameter
   Then: Return COMPLIANT

"""

import json
from datetime import datetime, timedelta
import boto3
import botocore
from dateutil import parser

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

# Set to True to get the lambda to assume the Role attached on the Config Service
# (useful for cross-account).
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
    valid_rule_parameters -- the output of the evaluate_parameters() representing validated
        parameters of the Config Rule

    Advanced Notes:
    1 -- if a resource is deleted and generate a configuration change with ResourceDeleted status,
        the Boilerplate code will put a NOT_APPLICABLE on this resource automatically.
    2 -- if a None or a list of dictionary is returned, the old evaluation(s) which are not
        returned in the new evaluation list are returned as NOT_APPLICABLE by the Boilerplate code
    3 -- if None or an empty string, list or dict is returned, the Boilerplate code will put a
        "shadow" evaluation to feedback that the evaluation took place properly
    """
    ec2_client = get_client('ec2', event)
    evaluations = []

    if configuration_item:
        ami_result = ec2_client.describe_images(
            ImageIds=[configuration_item['configuration']['imageId']]
        )
        print(ami_result)
        if ami_result['Images']:
            #print("AMI result:")
            #print(ami_result)
            status, annotation = evaluate_image(
                ami_result['Images'][0],
                configuration_item['configuration']['instanceId'],
                valid_rule_parameters
            )
            evaluations.append(
                build_evaluation_from_config_item(
                    configuration_item,
                    status,
                    annotation=annotation
                )
            )
        else:
            #Scenario 1 : No Private AMI for the Instance
            evaluations.append(
                build_evaluation_from_config_item(
                    configuration_item,
                    "NOT_APPLICABLE",
                    ""
                )
            )
    else:
        # First get all of the instances, paging through them if we have to.
        image_id_array = []
        instance_array = []

        instance_results = ec2_client.describe_instances()
        while True:
            for res in instance_results['Reservations']:
                for instance in res['Instances']:
                    image_id_array.append(instance['ImageId'])
                    instance_array.append(instance)
            if 'NextToken' in instance_results:
                next_token = instance_results['NextToken']
                instance_results = ec2_client.describe_instances(NextToken=next_token)
            else:
                break
        print(image_id_array)
        print(instance_array)

        # Use set() to get a list of just the unique image ID's.
        unique_image_ids = set(image_id_array)

        print(unique_image_ids)

        # Make as few API calls as possible to get the AMI data.  A simpler loop in
        # which we calling the EC2 API for every instance would be easier, but would
        # result in a _lot_ more API activity and could cause throttling.

        # Create a lookup dict so that we can evaluate compliance for each instance.
        image_lookup = {}

        image_results = ec2_client.describe_images(
            ImageIds=list(unique_image_ids)
        )
        while True:
            for image in image_results['Images']:
                image_lookup[image['ImageId']] = image

            if 'NextToken' in image_results:
                next_token = image_results['NextToken']
                image_results = ec2_client.describe_images(
                    ImageIds=list(unique_image_ids),
                    NextToken=next_token
                )
            else:
                break

        print(image_lookup)

        # Now loop through the instances again and determine the compliance status,
        # appending it to our evaluations list.
        for instance in instance_array:
            if instance['ImageId'] in image_lookup:
                status, annotation = evaluate_image(
                    image_lookup[instance['ImageId']],
                    instance['InstanceId'],
                    valid_rule_parameters
                )
                evaluations.append(
                    build_evaluation(
                        instance['InstanceId'],
                        status,
                        event,
                        "AWS::EC2::Instance",
                        annotation
                    )
                )
            else:
                #Scenario 1 : No Private AMIs in the account then no resources in scope
                evaluations.append(
                    build_evaluation(
                        instance['InstanceId'],
                        'NOT_APPLICABLE',
                        event,
                        "AWS::EC2::Instance"
                    )
                )

    return evaluations

def evaluate_image(ami, instance_id, valid_rule_parameters):
    image_whitelist = valid_rule_parameters['WhitelistedAmis'].split(",")

    #Scenario 9 - Whitelisted AMI
    if ami['ImageId'] in image_whitelist:
        return 'COMPLIANT', "ImageId in AMI Whitelist"

    instance_whitelist = valid_rule_parameters['WhitelistedInstances'].split(",")

    #Scenario 10 - Whitelisted Instance
    if instance_id in instance_whitelist:
        return 'COMPLIANT', "InstanceId in Instance Whitelist"

    #Scenario 5-8
    #   AMI age <= X days compliant.
    #   AMI age > X days non-compliant.

    creation_date = parser.parse(ami['CreationDate'])
    current_date = datetime.now(creation_date.tzinfo)
    elapsed_time = timedelta(days=valid_rule_parameters['NumberOfDays'])
    expiration_date = creation_date + elapsed_time

    if current_date <= expiration_date:
        ann = "AMI is less than " + str(valid_rule_parameters['NumberOfDays']) + " days old."
        return 'COMPLIANT', ann

    ann = "The AMI is older than " + str(valid_rule_parameters['NumberOfDays']) + " days."
    return 'NON_COMPLIANT', ann

def evaluate_parameters(rule_parameters):
    """
    Evaluate the rule parameters dictionary validity.
    Raise a ValueError for invalid parameters.

    Return:
    anything suitable for the evaluate_compliance()

    Keyword arguments:
    rule_parameters -- the Key/Value dictionary of the Config Rules parameters
    """
    # Scenario 2: Validate NumberOfDays parameter.
    if 'NumberOfDays' not in rule_parameters:
        raise ValueError('The Config Rule must have the parameter "NumberOfDays"')

    if not rule_parameters['NumberOfDays']:
        rule_parameters['NumberOfDays'] = 90

    #The int() function will raise an error if the string configured can't be converted to an integer
    #no rounding, truncating, or modification.
    try:
        rule_parameters['NumberOfDays'] = int(rule_parameters['NumberOfDays'])
    except ValueError:
        raise ValueError('The parameter "NumberOfDays" must be a integer')

    if rule_parameters['NumberOfDays'] < 1:
        raise ValueError('The parameter "NumberOfDays" must be greater than 1')

    #Scenario 3: Validate WhitelistedAmis parameter
    if 'WhitelistedAmis' not in rule_parameters:
        raise ValueError(
            'The Config Rule must have the parameter "WhitelistedAmis"'
        )
    else:
        if not isinstance(rule_parameters['WhitelistedAmis'], str):
            raise ValueError(
                'WhitelistedAmis must be a string or a list of strings separated by comma.'
            )
        else:
            rule_parameters['WhitelistedAmis'] = rule_parameters['WhitelistedAmis'].replace(" ", "")
            image_whitelist = rule_parameters['WhitelistedAmis'].split(",")
            if image_whitelist[0]:
                for ami_id in image_whitelist:
                    if not len(ami_id) >= 12:
                        raise ValueError(
                            'The element "' + ami_id + '" in parameter "WhitelistedAmis" is not the correct length.'
                        )
                    if not ami_id.startswith('ami-'):
                        raise ValueError(
                            'The element "' + ami_id + '" is not in the correct AMI ID format'
                        )

    #Scenario 4: Validate WhitelistedInstances parameter
    if 'WhitelistedInstances' not in rule_parameters:
        raise ValueError('The Config Rule must have the parameter "WhitelistedInstances"')
    else:
        if not isinstance(rule_parameters['WhitelistedInstances'], str):
            raise ValueError(
                'WhitelistedInstances must be a string or a list of strings separated by comma.'
            )
        else:
            rule_parameters['WhitelistedInstances'] = rule_parameters['WhitelistedInstances'].replace(" ", "")
            instance_whitelist = rule_parameters['WhitelistedInstances'].split(",")
            if instance_whitelist[0]:
                for instance_id in instance_whitelist:
                    if not len(instance_id) >= 10:
                        raise ValueError(
                            'The element "' + instance_id + '" in parameter "WhitelistedInstances" is not the correct length.'
                        )
                    if not instance_id.startswith('i-'):
                        raise ValueError(
                            'The element "' + instance_id + '" is not in the correct AMI ID format'
                        )

    return rule_parameters

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
# or using the getResourceConfigHistory API in getConfiguration function.
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
