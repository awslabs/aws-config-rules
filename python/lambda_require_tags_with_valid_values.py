#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that resources have required tags, and that tags have valid values.
#
# Trigger Type: Change Triggered
# Scope of Changes: AWS::Lambda::Function
# Accepted Parameters: requiredTagKey1, requiredTagValues1, requiredTagKey2, ...
# Example Values: 'CostCenter', 'R&D,Ops', 'Environment', 'Stage,Dev,Prod', ...
#                 An asterisk '*' as the value will just check that any value is set for that key


import json
import boto3


# Specify desired resource types to validate
APPLICABLE_RESOURCES = ["AWS::Lambda::Function"]


# Iterate through required tags ensureing each required tag is present, 
# and value is one of the given valid values
def find_violation(current_tags, required_tags):
    violation = ""
    for rtag,rvalues in required_tags.items():
        tag_present = False
        for tag in current_tags:
            if tag == rtag:
                tag_present = True
                value_match = False
                rvaluesplit = rvalues.split(",")
                for rvalue in rvaluesplit:
                    if current_tags[tag] == rvalue:
                        value_match = True
                    if current_tags[tag] != "":
                        if rvalue == "*":
                            value_match = True
                if value_match == False:
                    violation = violation + "\n" + current_tags[tag] + " doesn't match any of " + required_tags[rtag] + "!"
        if not tag_present:
            violation = violation + "\n" + "Tag " + str(rtag) + " is not present."
    if violation == "":
        return None
    return  violation


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


    if configuration_item["resourceType"] == "AWS::Lambda::Function":
        client = boto3.client('lambda')
        all_tags = client.list_tags(Resource=configuration_item["ARN"])
        current_tags = all_tags['Tags']  # get only user  tags.  


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
