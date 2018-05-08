#!/usr/bin/env python
"""
Checks if users comply to the following.

1. All active access keys have been used within the last ## days.
2. If console access is enabled check if login within the last ## days.
## is defined as an AWS Config rule parameter named "maxInactiveDays"
"""
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
###############################################################################
# Use Case:
#    Check if users password and access keys have recently been used
#    Return non-compliant when one of them has not been used within ## days
#    Where ## is specified by the parameter 'maxInactiveDays'
#
# Possible Results:
#    Result        - Annotation                             - Explanation
#    -----------------------------------------------------------------------------------------------------------------------------------
#    Compliant     - Compliant.                             - User has console access, has logged in recently, and access keys are good.
#    Compliant     - Compliant, console login is disabled.  - User does not have console access and access keys are good.
#    Non-Compliant - Access key has never been used.        - User has an access key generated but it has never been used.
#    Non-Compliant - Access key has not been used recently. - User has an access key but it has not been used recently.
#    Non-Compliant - Password has not been used recently.   - User has console access and has not logged in recently.
#    Non-Compliant - User has never logged in.              - User has console access but has never logged in.
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
#                "iam:GetUser",
#                "iam:ListAccessKeys",
#                "iam:GetAccessKeyLastUsed",
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
#        "ConfigRuleName": "User-Password-And-Keys-Age",
#        "Description": "Evaluates whether IAM users have used their login and access keys recently.",
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
#            },{
#                "EventSource": "aws.config",
#                "MaximumExecutionFrequency": "TwentyFour_Hours",
#                "MessageType": "ScheduledNotification"
#            }]
#        },
#        "InputParameters": "{\"maxInactiveDays\":\"60\"}"
#    }
###############################################################################
# 1.1.1 -- 2017/12/18
#   Fixed some comparisons to literals
#   Added more verbose instructions to comments
# 1.1.0
#   Written by AWS Professional Services Sr. Consultant Levi Romandine
#       Based on https://github.com/awslabs/aws-config-rules/tree/master/python
#       Combines iam-unused-user.py and iam-unused-keys.py
#   The annotation for failures and passes is now far more descriptive
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
import datetime
import json
import sys
import boto3
from botocore.exceptions import ClientError


DEBUG_FLAG = False


def calculate_age(date):
    """Return how many days between now and the given date."""
    now = datetime.datetime.utcnow().date()
    then = date.date()
    age = now - then
    return age.days


def get_user_name(configuration_item):
    """Return the user name for the given configuration item."""
    config = boto3.client("config")
    resource_information = config.get_resource_config_history(
        resourceType=configuration_item["resourceType"],
        resourceId=configuration_item["resourceId"]
        )
    return resource_information["configurationItems"][0]["resourceName"]


def check_access_keys(user_name, iam, max_inactive_days):
    """Check a given user's access keys for compliance."""
    try:
        user = iam.get_user(UserName=user_name)
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            # User was provided to the function but does not exist, nothing to do!
            print("Username '%s' was passed by config service but is not found, exiting gracefully." % user_name)
            sys.exit(0)
        else:
            print('Error getting IAM user details, error text follows:\n%s' % error)
            raise
    try:
        access_keys = iam.list_access_keys(UserName=user_name)
    except ClientError as error:
        print('ERROR: Unable to list access keys, error text is\n%s' % error)
    if len(access_keys["AccessKeyMetadata"]) is not 0:
        # has access keys
        for access_key in access_keys["AccessKeyMetadata"]:
            if access_key["Status"] == "Active":
                # only check active keys, deactivated are fine
                access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key["AccessKeyId"])
                if access_key_last_used["AccessKeyLastUsed"].get("LastUsedDate") is None:
                    # access key never used
                    return "NON_COMPLIANT", "Access key has never been used.", user
                else:
                    # access key has been used, check date
                    if calculate_age(access_key_last_used["AccessKeyLastUsed"].get("LastUsedDate")) > int(max_inactive_days):
                        # access key hasn't been used recently
                        return "NON_COMPLIANT", "Access key has not been used recently.", user
    # This point means access keys are good
    return None, None, user


def check_console_password(iam, user, user_name, max_inactive_days):
    """Check if the console password is allowed and recently used."""
    try:
        iam.get_login_profile(UserName=user_name)
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchEntity':
            return "COMPLIANT", "Compliant, console login is disabled."
        else:
            print('Error getting IAM user login profile details, error text follows:\n%s' % error)
            raise
    # This point means access keys are good and console login is disabled

    # This point means access keys are good, console login is enabled, check the password last used
    if user["User"].get("PasswordLastUsed") is not None:
        # Password has been used, how recently though?
        if calculate_age(user["User"].get("PasswordLastUsed")) > int(max_inactive_days):
            # password hasn't been used recently
            return "NON_COMPLIANT", "Password has not been used recently."
    else:
        # has never logged in
        return "NON_COMPLIANT", "User has never logged in."
    return "COMPLIANT", "Compliant."


def evaluate_compliance(configuration_item, max_inactive_days):
    """Evaluate the compliance of the given config item."""
    if configuration_item["resourceType"] not in ["AWS::IAM::User"]:
        return "NOT_APPLICABLE"
    user_name = get_user_name(configuration_item)
    iam = boto3.client("iam")
    compliance_type, annotation, user = check_access_keys(user_name, iam, max_inactive_days)
    if compliance_type is not None and annotation is not None:
        return compliance_type, annotation
    compliance_type, annotation = check_console_password(iam, user, user_name, max_inactive_days)
    return compliance_type, annotation


def lambda_handler(event, context):
    """Main."""
    if DEBUG_FLAG is True:
        print("Time remaining (MS):", context.get_remaining_time_in_millis())
    if "invokingEvent" in event:
        invoking_event = json.loads(event["invokingEvent"])
    else:
        print("event does not contain 'invokingEvent'")
        sys.exit(1)
    if "configurationItem" in invoking_event:
        configuration_item = invoking_event["configurationItem"]
    else:
        print("invoking_event does not contain 'configurationItem'")
        sys.exit(1)
    if "ruleParameters" in event:
        rule_parameters = json.loads(event["ruleParameters"])
    else:
        print("event does not contain 'ruleParameters'")
        sys.exit(1)
    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    config = boto3.client("config")
    compliance_type, annotation = evaluate_compliance(configuration_item, rule_parameters["maxInactiveDays"])
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType":
                    configuration_item["resourceType"],
                "ComplianceResourceId":
                    configuration_item["resourceId"],
                "ComplianceType":
                    compliance_type,
                "Annotation":
                    annotation,
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
                },
            ],
        ResultToken=result_token
        )
