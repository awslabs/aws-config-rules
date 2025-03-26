#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure Security Group do not have public accessible CIDR block
# Description: Checks Security Group if they have public access and removes it except the ones listed in the
# SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS parameter
#

# Lambda IAM Policy:
#   {
#        "Version": "2012-10-17",
#        "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": "ec2:RevokeSecurityGroupIngress",
#            "Resource": "*"
#        },
#        {
#             "Effect": "Allow",
#             "Action": "ec2:DescribeSecurityGroups",
#             "Resource": "*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": "config:PutEvaluations",
#            "Resource": "*"
#        }
#      ]
#   }
#
#
#
import json
import boto3
import botocore

# These security groups will not have their public accessible CIDR blocks removed
SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS = []

RESOURCE_TO_CHECK = ["AWS::EC2::SecurityGroup"]
COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_APPLICABLE = "NOT_APPLICABLE"


def evaluate_compliance(configuration_item):
    if configuration_item["resourceType"] not in RESOURCE_TO_CHECK:
        return {
            "compliance_type": NOT_APPLICABLE,
            "annotation": "The rule doesn't apply to resources of type " +
                          configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": NOT_APPLICABLE,
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }

    group_id = configuration_item["configuration"]["groupId"]
    client = boto3.client("ec2")

    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as exception_security_group:
        return {
            "compliance_type": NON_COMPLIANT,
            "annotation": "describe_security_groups failure on group " + group_id + " : " + exception_security_group
        }

    protocol_all = False

    compliance_type = COMPLIANT
    annotation_message = "Permissions are correct"

    if group_id not in SECURITY_GROUPS_ALLOWED_PUBLIC_ACCESS:
        # lets find public accessible CIDR Blocks
        for security_group_rule in response["SecurityGroups"][0]["IpPermissions"]:

            # if the rule is all protocol, FromPort is missing
            if "FromPort" not in security_group_rule:
                protocol_all = True

            for sg_name, val in security_group_rule.items():
                if sg_name == "IpRanges":
                    for resource in val:
                        annotation_message, compliance_type = validate_resource(annotation_message, client,
                                                                                group_id, protocol_all,
                                                                                resource, security_group_rule)

    return {
        "compliance_type": compliance_type,
        "annotation": annotation_message
    }


def validate_resource(annotation_message, client, group_id, protocol_all, resource,
                      security_group_rule):
    if resource["CidrIp"] in ["0.0.0.0/0", "::/0"]:
        print("Found Non Compliant Security Group: GroupID ", group_id)
        if not protocol_all:
            client.revoke_security_group_ingress(GroupId=group_id,
                                                 IpProtocol=security_group_rule[
                                                     "IpProtocol"],
                                                 CidrIp=resource["CidrIp"],
                                                 FromPort=security_group_rule["FromPort"],
                                                 ToPort=security_group_rule["ToPort"])
            compliance_type = COMPLIANT
            annotation_message = "Permissions were modified"
        else:
            client.revoke_security_group_ingress(GroupId=group_id,
                                                 IpProtocol=security_group_rule[
                                                     "IpProtocol"],
                                                 CidrIp=resource["CidrIp"])
            compliance_type = NON_COMPLIANT
    else:
        compliance_type = COMPLIANT
        annotation_message = "Permissions are correct"
    return annotation_message, compliance_type


def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]

    evaluation = evaluate_compliance(configuration_item)

    config = boto3.client('config')

    # the call to put_evalations is required to inform aws config about the changes
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation["compliance_type"],
                "Annotation": evaluation["annotation"],
                'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])
