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
from datetime import datetime, timezone


APPLICABLE_RESOURCES = ["AWS::IAM::User"]


def calculate_age(date):
    now = datetime.utcnow().date()
    then = date.date()
    age = now - then

    return age.days

def list_users():
    users = []
    ldr_pagination_token = ""
    config = boto3.client('config')

    while True:
        discovered_users_response = config.list_discovered_resources(
            resourceType="AWS::IAM::User",
            nextToken=ldr_pagination_token
        )
        users.extend(discovered_users_response["resourceIdentifiers"])
        if "nextToken" in discovered_users_response:
            ldr_pagination_token = discovered_users_response["nextToken"]
        else:
            break

    return users

def evaluate_configuration_change_compliance(configuration_item, rule_parameters):
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

def evaluate_scheduled_compliance(invoking_event, rule_parameters):
    evaluations = []
    users = list_users()
    iam = boto3.client("iam")
    max_inactive_days = int(rule_parameters["maxInactiveDays"])

    for user in users:
        user_name = user["resourceName"]
        user_iam = iam.get_user(UserName=user_name)
        last_used = user_iam["User"].get("PasswordLastUsed")

        if last_used is not None and calculate_age(last_used) > max_inactive_days:
            compliance = "NON_COMPLIANT"
        else:
            compliance = 'COMPLIANT'

        evaluations.append(
            {
                'ComplianceResourceType': user["resourceType"],
                'ComplianceResourceId': user["resourceId"],
                'ComplianceType': compliance,
                'OrderingTimestamp': datetime.now(timezone.utc)
            }
        )

    return evaluations

def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    rule_parameters = json.loads(event["ruleParameters"])

    if invoking_event["messageType"] == "ConfigurationItemChangeNotification":
        evaluations = []
        configuration_item = invoking_event["configurationItem"]
        compliance = evaluate_configuration_change_compliance(configuration_item, rule_parameters)
        evaluations.append(
            {
                'ComplianceResourceType': configuration_item["resourceType"],
                'ComplianceResourceId': configuration_item["resourceId"],
                'ComplianceType': compliance,
                'OrderingTimestamp': configuration_item["configurationItemCaptureTime"]
            }
        )
    elif invoking_event["messageType"] == "ScheduledNotification":
        evaluations = evaluate_scheduled_compliance(invoking_event, rule_parameters)
    else:
        raise Exception("Unexpected message type " + str(invoking_event))

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=evaluations,
        ResultToken=result_token
    )
