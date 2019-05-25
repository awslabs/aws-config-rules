#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that Secret LastChangedDate is no older than days specified
# Description: Checks that Secrets have been rotated since number of days
#
# Trigger Type: Periodic
# Scope of Changes: N/A
# Accepted Parameters: max_secret_age_days
# Example Values: 1, 2, 3,... default 30
#
# requires boto3 >= 1.9.152, botocore >= 1.12.152
# will fail without these library versions as pagination
# was not supported with the below libraries included
# in Lambda as of May 21st 2019
# Python 3.7 Lambda includes boto3 "1.9.42"
# Python 3.6 Lambda includes boto3 "1.7.74"
# You must use a custom deployment package that includes
# the required boto3 and botocore versions
# https://aws.amazon.com/premiumsupport/knowledge-center/build-python-lambda-deployment-package/

import json
import boto3
from datetime import datetime, timedelta, timezone

def evaluate_compliance(rule_parameters, secret):
    if 'max_secret_age_days' in rule_parameters:
        max_secret_age = datetime.now(timezone.utc) - timedelta(days=int(rule_parameters['max_secret_age_days']))
    else:
        max_secret_age = datetime.now(timezone.utc) - timedelta(days=30)

    if 'LastRotatedDate' in secret:
        if datetime.replace(secret['LastRotatedDate'],tzinfo=timezone.utc) > max_secret_age:
            return "COMPLIANT"
    elif datetime.replace(secret['LastChangedDate'],tzinfo=timezone.utc) > max_secret_age:
        return "COMPLIANT"
    else:
        return "NON_COMPLIANT"

def lambda_handler(event, context):
    if boto3.__version__ < '1.9.152':
        print('boto3 version too old for secret pagination')
        print('boto3 version: ' + boto3.__version__)
        exit(1)

    now = datetime.now(timezone.utc)
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])
    else:
        print('No rule paramters found')
        exit(1)
    result_token = 'No token found.'
    if 'resultToken' in event:
        result_token = event['resultToken']

    sm_client = boto3.client('secretsmanager')
    config = boto3.client('config')
    
    try:
        paginator = sm_client.get_paginator('list_secrets')
    except:
        print('Could not list_secrets')
        exit(1)

    for secret_list in paginator.paginate():
        for secret in secret_list['SecretList']:
            secret_arn = secret['ARN']
            config.put_evaluations(
                Evaluations=[
                    {
                        'ComplianceResourceType': 'AWS::SecretsManager::Secret',
                        'ComplianceResourceId': secret_arn,
                        'ComplianceType': evaluate_compliance(rule_parameters, secret),
                        'OrderingTimestamp': datetime(now.year, now.month, now.day, now.hour)
                    },
                ],
                ResultToken=event['resultToken']
            )
