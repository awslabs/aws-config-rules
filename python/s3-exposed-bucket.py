#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no buckets are globally accessible.
# Description: Checks that all buckets have some access restriction in place.
#
# Trigger Type: Change Triggered
# Scope of Changes: S3:Bucket


import json
import boto3


APPLICABLE_RESOURCES = ["AWS::S3::Bucket"]


def find_violation(resource_id):
    s3 = boto3.resource("s3")
    bucket = s3.Bucket(resource_id)
    acl = bucket.Acl()

    for grant in acl.grants:
        if "acs.amazonaws.com/groups/global/" in grant['Grantee']['URI']:
            return "The bucket is publicly accessible."

    return None


def evaluate_compliance(configuration_item, rule_parameters):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    resource_id = configuration_item["resourceId"]
    violation = find_violation(resource_id)

    if violation is not None:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": violation
        }
    else:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": "This resource is compliant with the rule."
        }


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = json.loads(event["ruleParameters"])

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType":
                    configuration_item["resourceType"],
                "ComplianceResourceId":
                    configuration_item["resourceId"],
                "ComplianceType":
                    evaluation["compliance_type"],
                "Annotation":
                    evaluation["annotation"],
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
