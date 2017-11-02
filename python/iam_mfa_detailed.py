#!/usr/bin/env python
"""This Lambda function will be invoked from AWS Config and check if all given IAM users have at least one MFA device."""
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
# Changelog
# 1.0.0
#   refactrored from
#       https://github.com/awslabs/aws-config-rules/blob/master/python/iam-mfa.py
#   Written by AWS Professional Services
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
DEBUG_MODE = True  # Manually change when debugging
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
    if len(mfa_response['MFADevices']) > 0:
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
