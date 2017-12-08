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
# AWS Config
# Trigger Type: Change Triggered and schedule (at least once every 24 hours)
# Scope of Changes: IAM:User
# Parameters: maxInactiveDays (integer)
###############################################################################
#   Annotation explanation
#       "COMPLIANT" annotations
#           Compliant.
#               This means the user has console access, has logged in recently, and access keys are good.
#           Compliant, console login is disabled.
#               This means the user does not have console access and access keys are good.
#       NON_COMPLIANT
#           Access key has never been used.
#               This means the user has an access key generated but it has never been used.
#           Access key has not been used recently.
#               This means the user has an access key but it has not been used recently.
#           Password has not been used recently.
#               This means the user has console access and has not logged in recently.
#           User has never logged in.
#               This means the user has console access but has never logged in.
###############################################################################
# 1.1.0
#   Written by AWS Professional Services Consultant Levi Romandine
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
