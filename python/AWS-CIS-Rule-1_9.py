#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# 1.9 Ensure IAM password policy requires minimum length of 14 or greater (Scored)
#

import boto3

def lambda_handler(event, context):
    #Create AWS clients
    iam = boto3.client('iam')
    config = boto3.client('config')

    #Get Account Password Policy
    response = iam.get_account_password_policy()
    pw_length = response['PasswordPolicy']['MinimumPasswordLength']
    
    #Evaluate Compliance
    if (pw_length < 14):
        return 'NON_COMPLIANT'
    else:
        return 'COMPLIANT'
