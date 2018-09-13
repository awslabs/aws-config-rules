#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no users have access keys that have never been used.
# Description: Checks that all users have only active access keys.
#
# Trigger Type: Change Triggered
# Scope of Changes: IAM:User


import json
import logging

import boto3

APPLICABLE_RESOURCES = ["AWS::IAM::User"]


def evaluate_compliance(configuration_item):
    compliant = "COMPLIANT"
    annotations = []

    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        compliant = "NOT_APPLICABLE"
        annotations.append(
            "Cannot use this rule for resource of type {}.".format(
                configuration_item["resourceType"]))

        return compliant, " ".join(annotations)

    user_name = configuration_item["configuration"]["userName"]

    iam = boto3.client("iam")
    access_keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]

    if access_keys:
        for access_key in access_keys:
            access_key_id = access_key["AccessKeyId"]
            access_key_status = access_key["Status"]

            last_used_date = iam.get_access_key_last_used(
                AccessKeyId=access_key_id
            ).get("AccessKeyLastUsed").get("LastUsedDate")

            if access_key_status == "Active" and last_used_date is None:
                compliant = "NON_COMPLIANT"
                annotations.append(
                    "Access key with ID {} was never used.".format(
                        access_key_id))
            else:
                annotations.append(
                    "Access key with ID {} key was last used {}.".format(
                        access_key_id, last_used_date))
    else:
        annotations.append("User do not have any active access key.")

    return compliant, " ".join(annotations)


def lambda_handler(event, context):
    logging.debug("Input event: %s", event)

    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    try:
        compliant, annotation = evaluate_compliance(configuration_item)

        config = boto3.client("config")
        config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType":
                        configuration_item["resourceType"],
                    "ComplianceResourceId":
                        configuration_item["resourceId"],
                    "ComplianceType": compliant,
                    "Annotation": annotation,
                    "OrderingTimestamp":
                        configuration_item["configurationItemCaptureTime"]
                },
            ],
            ResultToken=result_token,
        )
    except Exception as exception:
        logging.error("Error computing compliance status: %s", exception)
