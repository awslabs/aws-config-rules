# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
import json
import sys
import os
import datetime
import boto3
import botocore
import config_lambda_layer as cl
 
try:
    import liblogging
except ImportError:
    pass
 
##########
# Paramters #
##########
 
# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'
 
# Set to True to get the lambda to assume the Role attached on the Config Service (useful for cross-account).
ASSUME_ROLE_MODE = False
 
# Other parameters (no change needed)
CONFIG_ROLE_TIMEOUT_SECONDS = 900
 
config = boto3.client('config')
s3_client = boto3.client('s3')
 
#############
# Main Code #
#############

def assume_role(role_name):
    """Function to assume role from another account"""
    sts_connection = boto3.client('sts')
    master_account = sts_connection.assume_role(
        RoleArn=os.environ['OrgAssumableConfigRoleArn'],
        RoleSessionName="cross_acct_lambda"
    )
    access_key = master_account['Credentials']['AccessKeyId']
    secret_key = master_account['Credentials']['SecretAccessKey']
    session_token = master_account['Credentials']['SessionToken']

    client = boto3.client('organizations',
                          aws_access_key_id=access_key,
                          aws_secret_access_key=secret_key,
                          aws_session_token=session_token)

    return client


def get_accounts():
    client = assume_role(os.environ['OrgAssumableConfigRoleArn'])
    org_id = os.environ['OrganizationUnitId']
    accounts = []
    all_account_info = []
    response = client.list_accounts_for_parent(
        ParentId=org_id, MaxResults=20)
    all_account_info += response['Accounts']
    while 'NextToken' in response:
        response = client.list_accounts_for_parent(
            ParentId=org_id, MaxResults=20, NextToken=response['NextToken'])
        all_account_info += response['Accounts']

    for account in all_account_info:
        # Create list of accounts from OU
        accounts.append(account['Id'])
    return accounts
 

 
def evaluate_compliance(event, compliance, valid_rule_parameters):
    account_id = event['accountId']
    #account_ids = cl.get_accounts_in_same_ou_as(account_id, os.getenv('OrgAssumableConfigRoleArn', 'arn:invalid:check:env'))
    account_ids = get_accounts()
    account_ids.append(account_id)
    result = []
    compliance = ''
   
    bucket_names = s3_client.list_buckets()
    buckets = [bucket['Name']for bucket in bucket_names['Buckets']]
    policy = ''
    for bucket in buckets:
        bucket = bucket
        try:
            s3_policy = s3_client.get_bucket_policy(Bucket=bucket)
            policy = json.loads(s3_policy['Policy'])
        except:
            pass
   
        for statement in policy['Statement']:
                    principal = statement['Principal'] 
                    condition = ''
                    if 'Condition' in statement:
                        condition = statement['Condition']
                    if principal == "*" and not condition:
                        compliance = "NON_COMPLIANT"
                        annotation_string = "Principal index contains wildcard and not condition" 
                        break
                    elif principal != "*" and not condition:
                        for index in principal:
                            if "Service" in index:
                                compliance = "COMPLIANT"
                                annotation_string = "Principal index is valid "
                                continue
                            if  "AWS" in index:
                                compliance = "COMPLIANT"
                                annotation_string = "Principal index is valid " 
                            else:
                                compliance = "NON_COMPLIANT"
                                annotation_string = "Principal index is not AWS or Service " 
                                continue
                            if type(principal[index]) is list:
                                for value in principal[index]:
                                    if value == "*":
                                        compliance = "NON_COMPLIANT"
                                        annotation_string = "Principal index contains wildcard" 
                                        break
                                    if value.startswith('arn:'):
                                        value = value.split(':')[4]
                                    if value not in account_ids:
                                        compliance = "NON_COMPLIANT"
                                        annotation_string = "Target arn is not within <CUSTOMER> account (OU)." 
                                        break
                                    else:
                                        compliance = "COMPLIANT"
                                        continue
                                    if compliance == "NON_COMPLIANT":
                                        break
                                if compliance == "NON_COMPLIANT":
                                    break
                            elif type(principal[index]) is str:
                                value = principal[index]
                                if value.startswith('arn:'):
                                    value = value.split(':')[4]
                                if value not in account_ids:
                                    compliance = "NON_COMPLIANT"
                                    annotation_string = "Target arn is not within <CUSTOMER> account (OU)." 
                                    break
                                else:
                                     compliance = "COMPLIANT"
                                     continue
                    elif principal == "*" and condition:
                        if 'StringEquals' in condition:
                            if 'AWS:SourceOwner' in condition['StringEquals']:
                                value = condition['StringEquals']['AWS:SourceOwner']
                                if value in account_ids:
                                    compliance = "COMPLIANT"
                                    annotation_string = "Target arn is within <CUSTOMER> account (OU)." 
                                else:
                                    compliance = "NON_COMPLIANT"
                                    annotation_string = "Target arn is not within <CUSTOMER> account (OU)." 
                                    break
                            else:
                                compliance = "NON_COMPLIANT"
                                annotation_string = "SourceOwner is not in StringEquals condition1" 
                                break
                        elif 'Bool' in condition:
                            if 'aws:SecureTransport' in condition['Bool']:
                                 compliance = "COMPLIANT"
                                 annotation_string = "SecureTransport is in the condition"
                            else:
                                compliance = "NON_COMPLIANT"
                                annotation_string = "SecureTransport is not in Bool the condition" 
                                break
                        else:
                            compliance = "NON_COMPLIANT"
                            annotation_string = "StringEquals or Bool is incorrect in the condition" 
                            break
                    else:
                        for index in principal:
                            if "Service" in index:
                                compliance = "COMPLIANT"
                                annotation_string = "Principal index is valid " 
                                continue
                            if  "AWS" in index:
                                compliance = "COMPLIANT"
                                annotation_string = "Principal index is valid " 
                            else:
                                compliance = "NON_COMPLIANT"
                                annotation_string = "Principal index is not AWS or Service "
                                continue
                            if type(principal[index]) is list:
                                for value in principal[index]:
                                    if value == "*":
                                        if 'StringEquals' in condition:
                                            if 'AWS:SourceOwner' in condition['StringEquals']:
                                                value = condition['StringEquals']['AWS:SourceOwner']
                                                if value in account_ids:
                                                    compliance = "COMPLIANT"
                                                    annotation_string = "Target arn is within <CUSTOMER> account (OU)." 
                                                else:
                                                    compliance = "NON_COMPLIANT"
                                                    annotation_string = "Target arn is not within <CUSTOMER> account (OU)." 
                                                    break
                                            else:
                                                compliance = "NON_COMPLIANT"
                                                annotation_string = "SourceOwner is not in StringEquals condition1" 
                                                break
                                        elif 'Bool' in condition:
                                            if 'aws:SecureTransport' in condition['Bool']:
                                                 compliance = "COMPLIANT"
                                                 annotation_string = "SecureTransport is in condition1"
                                            else:
                                                compliance = "NON_COMPLIANT"
                                                annotation_string = "SecureTransport is not in Bool condition" 
                                                break
                                        else:
                                            compliance = "NON_COMPLIANT"
                                            annotation_string = "StringEquals or Bool is incorrect in condition" 
                                            break
                                    if value.startswith('arn:'):
                                        value = value.split(':')[4]
                                    if value not in account_ids:
                                        compliance = "NON_COMPLIANT"
                                        annotation_string = "Target arn is not within <CUSTOMER> account (OU). " 
                                        break
                                if compliance == "NON_COMPLIANT":
                                    break
                            elif type(principal[index]) is str:
                                value = principal[index]
                                if value != "*":
                                    if value.startswith('arn:'):
                                        value = value.split(':')[4]
                                    if value not in account_ids:
                                        compliance = "NON_COMPLIANT"
                                        annotation_string = "Target arn is not within <CUSTOMER> account (OU). " 
                                        break
                    
        result.append(cl.build_evaluation(bucket, compliance, event, DEFAULT_RESOURCE_TYPE, annotation_string))
    
    return result
           
    
 
##################
# Lambda Handler #
##################
 
def lambda_handler(event, context):
    if 'liblogging' in sys.modules:
        liblogging.logEvent(event)
 
    cl.check_defined(event, 'event')
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])
 
    try:
        valid_rule_parameters = cl.evaluate_parameters(rule_parameters)
    except ValueError as ex:
        return cl.build_parameters_value_error_response(ex)
 
    try:
        if invoking_event['messageType'] in ['ConfigurationItemChangeNotification', 'ScheduledNotification',
                                             'OversizedConfigurationItemChangeNotification']:
            configuration_item = cl.get_configuration_item(invoking_event)
            if cl.is_applicable(configuration_item, event):
                compliance_result = evaluate_compliance(event, configuration_item, valid_rule_parameters)
            else:
                compliance_result = "NOT_APPLICABLE"
        else:
            return cl.build_internal_error_response('Unexpected message type', str(invoking_event))
    except botocore.exceptions.ClientError as ex:
        if cl.is_internal_error(ex):
            return cl.build_internal_error_response("Unexpected error while completing API request", str(ex))
        return cl.build_error_response("Customer error while making API request", str(ex), ex.response['Error']['Code'],
                                       ex.response['Error']['Message'])
    except ValueError as ex:
        return cl.build_internal_error_response(str(ex), str(ex))
 
    evaluations = []
    latest_evaluations = []
 
    if not compliance_result:
        latest_evaluations.append(
            cl.build_evaluation(event['accountId'], "NOT_APPLICABLE", event, resource_type='AWS::::Account'))
        evaluations = cl.clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, str):
        if configuration_item:
            evaluations.append(cl.build_evaluation_from_config_item(configuration_item, compliance_result))
        else:
            evaluations.append(
                cl.build_evaluation(event['accountId'], compliance_result, event, resource_type=DEFAULT_RESOURCE_TYPE))
    elif isinstance(compliance_result, list):
        for evaluation in compliance_result:
            missing_fields = False
            for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
                if field not in evaluation:
                    print("Missing " + field + " from custom evaluation.")
                    missing_fields = True
 
            if not missing_fields:
                latest_evaluations.append(evaluation)
        evaluations = cl.clean_up_old_evaluations(latest_evaluations, event)
    elif isinstance(compliance_result, dict):
        missing_fields = False
        for field in ('ComplianceResourceType', 'ComplianceResourceId', 'ComplianceType', 'OrderingTimestamp'):
            if field not in compliance_result:
                print("Missing " + field + " from custom evaluation.")
                missing_fields = True
        if not missing_fields:
            evaluations.append(compliance_result)
    else:
        evaluations.append(cl.build_evaluation_from_config_item(configuration_item, 'NOT_APPLICABLE'))
 
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
        config.put_evaluations(Evaluations=evaluation_copy[:100], ResultToken=result_token, TestMode=test_mode)
        del evaluation_copy[:100]
 
    # Used solely for RDK test to be able to test Lambda function
    return evaluations