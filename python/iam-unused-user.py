#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that there are no users that have never been logged in.
# Description: Checks that all users have logged in at least once.
#
# Trigger Type: Change Triggered
# Scope of Changes: IAM:User


import json
import boto3


APPLICABLE_RESOURCES = ["AWS::IAM::User"]


def evaluate_compliance(configuration_item):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return "NOT_APPLICABLE"

    config = boto3.client("config")
    resource_information = config.get_resource_config_history(
        resourceType=configuration_item["resourceType"],
        resourceId=configuration_item["resourceId"]
    )
    user_name = resource_information["configurationItems"][0]["resourceName"]

    iam = boto3.client("iam")
    user = iam.get_user(UserName=user_name)

    if user["User"].get("PasswordLastUsed") is None:
        return "NON_COMPLIANT"

    return "COMPLIANT"


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
                    "The user has never logged in.",
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
