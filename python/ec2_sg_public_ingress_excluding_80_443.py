#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
# 
# Ensure that no EC2 Instances is publicly accessible except 80 and 443.
# Description: Check that no security groups allow public access to the ports other then 80 and 443.
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance
# Accepted Parameters: None
# Your Lambda function execution role will need to have a policy that provides the appropriate
# permissions.  Here is a policy that you can consider.  You should validate this for your own
# environment
#{
#    "Version": "2012-10-17",
#    "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": [
#                "logs:CreateLogGroup",
#                "logs:CreateLogStream",
#                "logs:PutLogEvents"
#            ],
#            "Resource": "arn:aws:logs:*:*:*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "config:PutEvaluations",
#                "ec2:DescribeSecurityGroups"
#            ],
#            "Resource": "*"
#        }
#    ]
#}
#

import boto3
import botocore
import json
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)

def evaluate_compliance(configuration_item):
    sg      = configuration_item["configuration"]["securityGroups"]
    sg_ids  = []
    non_compliant_sg    = []
    
    for i in sg:
        sg_ids.append(i['groupId'])

    client      = boto3.client("ec2");

    try:
        response    = client.describe_security_groups(GroupIds=sg_ids)
    except botocore.exceptions.ClientError as e:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : "describe_security_groups failure on group " + str(sg_ids)
        }

    for sgs in response['SecurityGroups']:
        for ingress in sgs['IpPermissions']:
            if ingress['FromPort'] != 80 and ingress['FromPort'] != 443:
                for cidr in ingress['IpRanges']:
                    if cidr['CidrIp'] == '0.0.0.0/0':
                        non_compliant_sg.append(sgs['GroupId'])

    if non_compliant_sg:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : 'There exists some ingress ports other than 80 and 443 which are publicly accessible ' + str(set(non_compliant_sg))
        }

    return {
        "compliance_type": "COMPLIANT",
        "annotation": 'None of the security groups ingress ports other than 80 and 443 which are publicly accessible'
    }

def lambda_handler(event, context):
    log.debug('Event %s', event)
    invoking_event      = json.loads(event['invokingEvent'])
    configuration_item  = invoking_event["configurationItem"]
    evaluation          = evaluate_compliance(configuration_item)
    config              = boto3.client('config')

    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType':    invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId':      invoking_event['configurationItem']['resourceId'],
               'ComplianceType':            evaluation["compliance_type"],
               "Annotation":                evaluation["annotation"],
               'OrderingTimestamp':         invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])
