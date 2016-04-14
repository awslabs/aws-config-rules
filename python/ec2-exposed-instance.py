#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no EC2 instances allow public access to the specified ports.
# Description: Checks that all instances block access to the specified ports.
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance
# Accepted Parameters: examplePort1, exampleRange1, examplePort2, ...
# Example Values: 8080, 1-1024, 2375, ...


import json
import boto3


APPLICABLE_RESOURCES = ["AWS::EC2::Instance"]


def explode_range(ports):
    if "-" in ports:
        return range(int(ports.split("-")[0]), int(ports.split("-")[1]))
    else:
        return int(ports)


def find_exposed_ports(ip_permissions):
    exposed_ports = []
    for permission in ip_permissions:
        if next((r for r in permission["IpRanges"]
                if "0.0.0.0/0" in r["CidrIp"]), None):
                    exposed_ports.extend(range(permission["FromPort"],
                                               permission["ToPort"]))
    return exposed_ports


def find_violation(ip_permissions, forbidden_ports):
    exposed_ports = find_exposed_ports(ip_permissions)
    for forbidden in forbidden_ports:
        ports = explode_range(forbidden_ports[forbidden])
        for port in ports:
            if port in exposed_ports:
                return "A forbidden port is exposed to the internet."
            else:
                return None


def evaluate_compliance(configuration_item, rule_parameters):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    ec2 = boto3.resource("ec2")
    instance = ec2.Instance(configuration_item["resourceId"])
    security_groups = instance.security_groups

    for security_group in security_groups:
        ip_permissions = ec2.SecurityGroup(
                                           security_group["GroupId"]
                                          ).ip_permissions

        violation = find_violation(
            ip_permissions,
            rule_parameters
        )

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
