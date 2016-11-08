#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
# 
# Description: Check that no RDS Instances are in Public Subnet
#
# Trigger Type: Change Triggered
# Scope of Changes: RDS:DBInstance
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
#                "ec2:DescribeRouteTables"
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
    vpc_id      = configuration_item["configuration"]['dBSubnetGroup']["vpcId"]
    subnet_id   = []
    for i in configuration_item["configuration"]['dBSubnetGroup']['subnets']:
        subnet_id.append(i['subnetIdentifier'])
    client      = boto3.client("ec2");
    private     = True

    response    = client.describe_route_tables()
    # If only default route table exists then
    # all subnets are automatically attached to this route table
    # Otherwise check if subnet is explicitly attached to another route table
    # Private subnet condition applies only when route doesn't contains
    # destination CIDR block = 0.0.0.0/0 or no Internet Gateway is attached
    for i in response['RouteTables']:
        if i['VpcId'] == vpc_id:
            for j in i['Associations']:
                if j['Main'] == True:
                    for k in i['Routes']:
                        if k['DestinationCidrBlock'] == '0.0.0.0/0' or k['GatewayId'].startswith('igw-'):
                            private = False
                else:
                    if j['SubnetId'] in subnet_id:
                        for k in i['Routes']:
                            if k['DestinationCidrBlock'] == '0.0.0.0/0' or k['GatewayId'].startswith('igw-'):
                                private = False
    
    if private:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": 'Its in private subnet'
        }
    else:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : 'Not in private subnet'
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
