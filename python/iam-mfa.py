#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no users have multiple factor authentication disabled.
# Description: Checks that all users have enabled multiple factor authentication.
#
# Trigger Type: Change Triggered
# Scope of Changes: IAM:User


import json
import boto3


APPLICABLE_RESOURCES = ["AWS::IAM::User"]


def evaluate_compliance(configuration_item):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return "NOT_APPLICABLE"

    user_name = configuration_item["configuration"]["userName"]

    iam = boto3.client("iam")
    mfa = iam.list_mfa_devices(UserName=user_name)

    if len(mfa["MFADevices"]) > 0:
        return "COMPLIANT"
    else:
        return "NON_COMPLIANT"


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType":
                    configuration_item["resourceType"],
                "ComplianceResourceId":
                    configuration_item["resourceId"],
                "ComplianceType":
                    evaluate_compliance(configuration_item),
                "Annotation":
                    "The user doesn't have MFA enabled.",
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
