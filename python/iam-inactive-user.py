#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no users have been inactive for a period longer than specified.
# Description: Checks that all users have been active for earlier than specified.
#
# Trigger Type: Change Triggered
# Scope of Changes: IAM:User
# Required Parameters: maxInactiveDays
# Example Value: 90


import json
import boto3
import datetime


APPLICABLE_RESOURCES = ["AWS::IAM::User"]


def calculate_age(date):
    now = datetime.datetime.utcnow().date()
    then = date.date()
    age = now - then

    return age.days


def evaluate_compliance(configuration_item, rule_parameters):
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
    last_used = user["User"].get("PasswordLastUsed")
    max_inactive_days = int(rule_parameters["maxInactiveDays"])

    if last_used is not None and calculate_age(last_used) > max_inactive_days:
        return "NON_COMPLIANT"

    return "COMPLIANT"


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = json.loads(event["ruleParameters"])

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
                    evaluate_compliance(configuration_item, rule_parameters),
                "Annotation":
                    "The user has never logged in.",
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
