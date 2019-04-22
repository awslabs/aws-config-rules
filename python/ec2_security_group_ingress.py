#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# ec2_security_group_ingress.py
# Trigger Type: Change Triggered
#
# Date: 2016-09-25
#
# This file contains an AWS Lambda handler which responds to AWS Config triggers in AWS EC2 security groups.
# The Lambda function examines changes in the security group ingress permissions to see if they differ from
# the required permissions as specificed in the REQUIRED_PERMISSIONS variable below.   If so, the Lambda
# function adds or removes ingress ports as needed.  Egress rules are not checked.
#
# Your Lambda function execution role will need to have a policy that provides the appropriate
# permissions.  Here is a policy that you can consider.  You should validate this for your own
# environment
#
#{
#   "Version": "2012-10-17",
#   "Statement": [
#       {
#           "Effect": "Allow",
#           "Action": [
#               "logs:CreateLogGroup",
#               "logs:CreateLogStream",
#               "logs:PutLogEvents"
#           ],
#           "Resource": "arn:aws:logs:*:*:*"
#       },
#       {
#           "Effect": "Allow",
#           "Action": [
#               "config:PutEvaluations",
#               "ec2:DescribeSecurityGroups",
#               "ec2:AuthorizeSecurityGroupIngress",
#               "ec2:RevokeSecurityGroupIngress"
#           ],
#           "Resource": "*"
#       }
#   ]
#}
#
# NOTES:
#
# This code is only intended for instructional purposes and should not be used for any other use.

import boto3
import botocore
import json

 
APPLICABLE_RESOURCES = ["AWS::EC2::SecurityGroup"]

# Specify the required ingress permissions using the same key layout as that provided in the
# describe_security_group API response and authorize_security_group_ingress/egress API calls.

REQUIRED_PERMISSIONS = [
{
    "IpProtocol" : "tcp",
    "FromPort" : 80,
    "ToPort" : 80,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "0.0.0.0/0"}],
    "PrefixListIds" : [],
    "Ipv6Ranges" : []
},
{
    "IpProtocol" : "tcp",
    "FromPort" : 443,
    "ToPort" : 443,
    "UserIdGroupPairs" : [],
    "IpRanges" : [{"CidrIp" : "0.0.0.0/0"}],
    "PrefixListIds" : [],
    "Ipv6Ranges" : []
}]

# normalize_parameters
#
# Normalize all rule parameters so we can handle them consistently.
# All keys are stored in lower case.  Only boolean and numeric keys are stored.

def normalize_parameters(rule_parameters):
    for key, value in rule_parameters.iteritems():
        normalized_key=key.lower()
        normalized_value=value.lower()

        if normalized_value == "true":
            rule_parameters[normalized_key] = True
        elif normalized_value == "false":
            rule_parameters[normalized_key] = False
        elif normalized_value.isdigit():
            rule_parameters[normalized_key] = int(normalized_value)
        else:
            rule_parameters[normalized_key] = True
    return rule_parameters

# evaluate_compliance
#
# This is the main compliance evaluation function.
#
# Arguments:
#
# configuration_item - the configuration item obtained from the AWS Config event
# debug_enabled - debug flag
#
# return values:
#
# compliance_type -
#
#     NOT_APPLICABLE - (1) something other than a security group is being evaluated
#                      (2) the configuration item is being deleted
#     NON_COMPLIANT  - the rules do not match the required rules and we couldn't
#                      fix them
#     COMPLIANT      - the rules match the required rules or we were able to fix
#                      them
#
# annotation         - the annotation message for AWS Config

def evaluate_compliance(configuration_item, debug_enabled):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type" : "NOT_APPLICABLE",
            "annotation" : "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    if configuration_item["configurationItemStatus"] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted and therefore cannot be validated."
        }

    group_id = configuration_item["configuration"]["groupId"]
    client = boto3.client("ec2");

    # Call describe_security_groups because the IpPermissions that are returned
    # are in a format that can be used as the basis for input to
    # authorize_security_group_ingress and revoke_security_group_ingress.

    try:
        response = client.describe_security_groups(GroupIds=[group_id])
    except botocore.exceptions.ClientError as e:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : "describe_security_groups failure on group " + group_id
        }
        
    if debug_enabled:
        print("security group definition: ", json.dumps(response, indent=2))

    ip_permissions = response["SecurityGroups"][0]["IpPermissions"]
    authorize_permissions = [item for item in REQUIRED_PERMISSIONS if item not in ip_permissions]
    revoke_permissions = [item for item in ip_permissions if item not in REQUIRED_PERMISSIONS]

    if authorize_permissions or revoke_permissions:
        annotation_message = "Permissions were modified."
    else:
        annotation_message = "Permissions are correct."

    if authorize_permissions:
        if debug_enabled:
            print("authorizing for ", group_id, ", ip_permissions ", json.dumps(authorize_permissions, indent=2))

        try:
            client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=authorize_permissions)
            annotation_message += " " + str(len(authorize_permissions)) +" new authorization(s)."
        except botocore.exceptions.ClientError as e:
            return {
                "compliance_type" : "NON_COMPLIANT",
                "annotation" : "authorize_security_group_ingress failure on group " + group_id
            }

    if revoke_permissions:
        if debug_enabled:
            print("revoking for ", group_id, ", ip_permissions ", json.dumps(revoke_permissions, indent=2))

        try:
            client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke_permissions)
            annotation_message += " " + str(len(revoke_permissions)) +" new revocation(s)."
        except botocore.exceptions.ClientError as e:
            return {
                "compliance_type" : "NON_COMPLIANT",
                "annotation" : "revoke_security_group_ingress failure on group " + group_id
            }

    return {
        "compliance_type": "COMPLIANT",
        "annotation": annotation_message
    }

# lambda_handler
# 
# This is the main handle for the Lambda function.  AWS Lambda passes the function an event and a context.
# If "debug" is specified as a rule parameter, then debugging is enabled.

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = normalize_parameters(json.loads(event["ruleParameters"]))

    debug_enabled = False

    if "debug" in rule_parameters:
        debug_enabled = rule_parameters["debug"] 

    if debug_enabled:
        print("Received event: " + json.dumps(event, indent=2))

    evaluation = evaluate_compliance(configuration_item, debug_enabled)

    config = boto3.client('config')

    response = config.put_evaluations(
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
