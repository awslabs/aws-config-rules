#!/usr/bin/env python
"""This Lambda function will be invoked from AWS Config and check if all given IAM users have MFA device, if they have console access."""
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
################################################################################
# Use Case:
#    Log detailed information about IAM users and their MFA tokens
#
# Possible Results:
#    Result        - Annotation
#    -----------------------------------------------------
#    Compliant     - The user has MFA enabled.
#    Compliant     - Compliant, console login is disabled.
#    Non-Compliant - The user does not have MFA enabled.
#
# Lambda Function Details:
#    Runtime: python 2.7
#    Memory: 128 MB
#    Timeout: 30 seconds
#
# Expected Input (Only to be ran from AWS Config, this is a sample event):
#    {
#        "invokingEvent": {
#            "configurationItemDiff": null,
#            "configurationItem": {
#                "relatedEvents": [],
#                "relationships": [],
#                "configuration": {
#                    "path": "/",
#                    "userName": "config-test-user1",
#                    "userId": "AIDAIEJCNPAE4EONMASRY",
#                    "arn": "arn:aws:iam::123456789012:user/config-test-user1",
#                    "createDate": "2017-03-22T18:29:26.000Z",
#                    "userPolicyList": [],
#                    "groupList": [],
#                    "attachedManagedPolicies": [{
#                        "policyName": "IAMUserChangePassword",
#                        "policyArn": "arn:aws:iam::aws:policy/IAMUserChangePassword"
#                    }]
#                },
#                "supplementaryConfiguration": {},
#                "tags": {},
#                "configurationItemVersion": "1.2",
#                "configurationItemCaptureTime": "2017-07-27T20:07:35.770Z",
#                "configurationStateId": 1501186055770,
#                "awsAccountId": "123456789012",
#                "configurationItemStatus": "OK",
#                "resourceType": "AWS::IAM::User",
#                "resourceId": "AIDAIEJCNPAE4EONMASRY",
#                "resourceName": "config-test-user1",
#                "ARN": "arn:aws:iam::123456789012:user/config-test-user1",
#                "awsRegion": "global",
#                "availabilityZone": "Not Applicable",
#                "configurationStateMd5Hash": "4a51983c20f27f28c58011a5547d6cd3",
#                "resourceCreationTime": "2017-03-22T18:29:26.000Z"
#            },
#            "notificationCreationTime": "2017-12-19T04:52:22.933Z",
#            "messageType": "ConfigurationItemChangeNotification",
#            "recordVersion": "1.2"
#        }
#    }
#
# Expected Output:
#    None, sends all compliance data directly to AWS Config
#
# IAM Role Policy Example:
#    {
#        "Version": "2012-10-17",
#        "Statement": [{
#            "Effect": "Allow",
#            "Action": ["s3:GetObject"],
#            "Resource": "arn:aws:s3:::*/AWSLogs/*/Config/*"
#        }, {
#            "Effect": "Allow",
#            "Action": [
#                "config:Put*",
#                "config:Get*",
#                "config:List*",
#                "config:Describe*"
#            ],
#            "Resource": "*"
#        }, {
#            "Effect": "Allow",
#            "Action": [
#                "iam:ListMFADevices",
#                "iam:GetLoginProfile"
#            ],
#            "Resource": "*"
#        }, {
#            "Effect": "Allow",
#            "Action": [
#                "logs:CreateLogStream",
#                "logs:PutLogEvents",
#                "logs:CreateLogGroup"
#            ],
#            "Resource": "*"
#        }]
#    }
#
# Example AWS Lambda Function Permission:
#    aws lambda add-permission \
#        --function-name <<YOUR_LAMBDA_NAME>> \
#        --statement-id 1 \
#        --principal config.amazonaws.com \
#        --action lambda:InvokeFunction \
#        --source-account <<YOUR_ACCOUNT_NUMBER>>
#
# Example AWS Config Rule Creation CLI Command:
#    aws configservice put-config-rule --config-rule file://rule.json
#
# Example AWS Config Rule Creation JSON for CLI Command:
#    {
#        "ConfigRuleName": "Detailed-MFA-Check",
#        "Description": "Evaluates whether IAM users have MFA enabled if they have console access.",
#        "Scope": {
#            "ComplianceResourceTypes": [
#                "AWS::IAM::User"
#            ]
#        },
#        "Source": {
#            "Owner": "CUSTOM_LAMBDA",
#            "SourceIdentifier": "<<YOUR_LAMBDA_ARN_HERE>>",
#            "SourceDetails": [{
#                "EventSource": "aws.config",
#                "MessageType": "ConfigurationItemChangeNotification"
#            }]
#        }
#    }
################################################################################
# Changelog
# 1.0.1 -- 2017/12/18
#   Fixed linter warning
#   Added more verbose instructions to comments
# 1.0.0
#   refactored from
#       https://github.com/awslabs/aws-config-rules/blob/master/python/iam-mfa.py
#   Written by AWS Professional Services Sr. Consultant Levi Romandine
#   Made compliant with major Python linters
#     flake8 (pep8 & pyflakes)
#       Disabled E501 (line length)
#       Disabled E241 (whitespace after comma)
#     OpenStack Style Guide
#       Disabled H306 (alphabetize imports)
#     pep257
#     pycodestyle
#     pylint
#       Disabled C0301 (line length)
#       Disabled C0326 (whitespace after comma)
from __future__ import print_function
import json
import boto3
from botocore.exceptions import ClientError


print('Loading function...')
DEBUG_MODE = False  # Manually change when debugging
try:
    IAM_CLIENT = boto3.client('iam')
    CONFIG_CLIENT = boto3.client('config')
except Exception as error:
    print('Error creating boto3.client for S3, error text follows:\n%s' % error)
    raise Exception(error)


def evaluate_compliance(configuration_item):
    """Check if given IAM user has a MFA device and return a string to be used for AWS config put_evaluations."""
    if configuration_item['resourceType'] not in ['AWS::IAM::User']:
        return 'NOT_APPLICABLE', 'Not applicable.'
    if DEBUG_MODE is True:
        print('Checking user %s for compliance...' % str(configuration_item['configuration']['userName']))
    try:
        mfa_response = IAM_CLIENT.list_mfa_devices(
            UserName=configuration_item['configuration']['userName']
            )
    except Exception as error:
        print('Error listing IAM devices for user, error text follows:\n%s' % error)
        raise Exception(error)
    if mfa_response['MFADevices']:
        if DEBUG_MODE is True:
            print('User %s is COMPLIANT.' % str(configuration_item['configuration']['userName']))
        return 'COMPLIANT', 'The user has MFA enabled.'
    else:
        try:
            IAM_CLIENT.get_login_profile(
                UserName=configuration_item['configuration']['userName']
                )
        except ClientError as error:
            if error.response['Error']['Code'] == 'NoSuchEntity':
                return "COMPLIANT", "Compliant, console login is disabled."
            else:
                print('Error response is:\n%s' % str(error.response))
                print('Error getting IAM user login profile details, error text follows:\n%s' % error)
                raise Exception(error)
        if DEBUG_MODE is True:
            print('User %s is NON_COMPLIANT.' % str(configuration_item['configuration']['userName']))
        return 'NON_COMPLIANT', 'The user does not have MFA enabled.'


def validate_invoking_event(event):
    """Verify the invoking event has all the necessary data fields."""
    if 'invokingEvent' in event:
        invoking_event = json.loads(event['invokingEvent'])
    else:
        raise Exception('Error, invokingEvent not found in event, aborting.')
    if 'resultToken' not in event:
        raise Exception('Error, resultToken not found in event, aborting.')
    if 'configurationItem' not in invoking_event:
        raise Exception("Error, configurationItem not found in event['invokingEvent'], aborting.")
    if 'resourceType' not in invoking_event['configurationItem']:
        raise Exception("Error, resourceType not found in event['invokingEvent']['configurationItem'], aborting.")
    if 'configuration' not in invoking_event['configurationItem']:
        raise Exception("Error, configuration not found in event['invokingEvent']['configurationItem'], aborting.")
    if 'userName' not in invoking_event['configurationItem']['configuration']:
        raise Exception("Error, userName not found in event['invokingEvent']['configurationItem']['configuration'], aborting.")
    if 'resourceId' not in invoking_event['configurationItem']:
        raise Exception("Error, resourceId not found in event['invokingEvent']['configurationItem'], aborting.")
    if 'configurationItemCaptureTime' not in invoking_event['configurationItem']:
        raise Exception("Error, configurationItemCaptureTime not found in event['invokingEvent']['configurationItem'], aborting.")
    return invoking_event


def lambda_handler(event, context):  # pylint: disable=W0613
    """Main Lambda function."""
    if DEBUG_MODE is True:
        print("Received event: \n%s" % json.dumps(event, indent=2))
    invoking_event = validate_invoking_event(event)
    try:
        compliance, annotation = evaluate_compliance(invoking_event['configurationItem'])
        CONFIG_CLIENT.put_evaluations(
            Evaluations=[
                {
                    'ComplianceResourceType':
                        invoking_event['configurationItem']['resourceType'],
                    'ComplianceResourceId':
                        invoking_event['configurationItem']['resourceId'],
                    'ComplianceType':
                        compliance,
                    'Annotation':
                        annotation,
                    'OrderingTimestamp':
                        invoking_event['configurationItem']['configurationItemCaptureTime']
                    },
                ],
            ResultToken=event['resultToken']
            )
    except Exception as error:
        print('Error submitting put_evaluation to AWS config, error text follows:\n%s' % error)
        raise Exception(error)
