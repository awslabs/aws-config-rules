#
# This file made available under CC0 1.0 Universal
# (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no S3 bucket allow public access.
# Description: Checks that all S3 buckets block access on the ACL and bucket
# policy level.
#
# Trigger Type: Change Triggered
# Scope of Changes: S3:Bucket


import json
import boto3


APPLICABLE_RESOURCES = ["AWS::S3::Bucket"]


def validate_policy(policy_text):
    if policy_text is None:
        # The Bucket Policy is not set and therefore cannot be validated
        return False
    policy = json.loads(policy_text)
    for s in policy["Statement"]:
        if s["Effect"] == "Allow" and s["Principal"] == "*":
            return True
    return False


def validate_acl(bucket_acl):
    for g in bucket_acl["grantList"]:
        if "AllUsers" in str(g.get("grantee")) or \
           "AuthenticatedUsers" in str(g.get("grantee")):
            return True
    return False


def evaluate_compliance(configuration_item, rule_parameters):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    if configuration_item['configurationItemStatus'] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted " +
                          "and therefore cannot be validated"
        }

    bucket_acl = configuration_item["supplementaryConfiguration"].get(
                                                        "AccessControlList")
    bucket_policy = configuration_item["supplementaryConfiguration"].get(
                                                        "BucketPolicy")

    violation = validate_policy(bucket_policy['policyText'])

    if violation:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": "The Bucket Policy allows dangerous access"
        }

    violation = validate_acl(json.loads(bucket_acl))

    if violation:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": "The Bucket ACL allows dangerous access"
        }

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
