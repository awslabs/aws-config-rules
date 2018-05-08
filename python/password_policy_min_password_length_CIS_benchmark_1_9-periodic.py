#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# CIS Amazon Web Services Foundations Benchmark 1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
#
# Trigger Type: Periodic

import boto3, json

def lambda_handler(event, context):
    #Create AWS clients
    iam = boto3.client('iam')
    config = boto3.client('config')
    
    #Create current invokation info
    invoking_event = json.loads(event['invokingEvent'])
    compliance_value = 'NOT_APPLICABLE'
    account_id = event['accountId']
            
    #Get Account Password Policy
    response = iam.get_account_password_policy()
    pw_length = response['PasswordPolicy']['MinimumPasswordLength']
    
    #Evaluate Compliance
    if (pw_length < 14):
        compliance_value = 'NON_COMPLIANT'
    else:
        compliance_value = 'COMPLIANT'
        
    response = config.put_evaluations(
       Evaluations=[
            {
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': account_id,
                'ComplianceType': compliance_value,
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            },
       ],
       ResultToken=event['resultToken'])
