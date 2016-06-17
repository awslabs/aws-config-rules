#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that resources have required tags, and that tags have valid values.
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance
# Accepted Parameters: requiredTagKey1, requiredTagValues1, requiredTagKey2, ...
# Example Values: 'CostCenter', 'R&D,Ops', 'Environment', 'Stage,Dev,Prod', ...


import json
import boto3


# Specify desired resource types to validate
APPLICABLE_RESOURCES = ["AWS::EC2::Instance"]


# Iterate through required tags ensureing each required tag is present, 
# and value is one of the given valid values
def find_violation(current_tags, required_tags):
    required_tag_count = len(required_tags) / 2
    for x in range(1, required_tag_count + 1):
        tag_present = False
        for tag in current_tags:
            if tag["key"] == required_tags["requiredTagKey"+str(x)]:
                tag_present = True
                if not tag["value"] in required_tags["requiredTagValues"+str(x)].split(','):
                    return "Tag '" + required_tags["requiredTagKey"+str(x)] + "' value '" + tag["value"] + "' is not a valid value."
        if not tag_present:
            return "Tag '" + required_tags["requiredTagKey"+str(x)] + "' is not present."

    return None

def evaluate_compliance(configuration_item, rule_parameters):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }

    current_tags = configuration_item["configuration"].get("tags")
    violation = find_violation(current_tags, rule_parameters)        

    if violation:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": violation
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