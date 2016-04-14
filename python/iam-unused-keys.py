#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no users have access keys that have never been used.
# Description: Checks that all users have only active access keys.
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
    access_keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

    for access_key in access_keys:
        access_key_id = access_key["AccessKeyId"]
        access_key_status = access_key["Status"]
        last_used = iam.get_access_key_last_used(AccessKeyId=access_key_id)
        if access_key_status is "Active" and \
                last_used.get("LastUsedDate") is None:
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
                    "The user hasn't logged in for a long time.",
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
