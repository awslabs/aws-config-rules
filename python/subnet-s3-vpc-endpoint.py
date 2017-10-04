 This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
# 
# Description: Check that Subnets have a VPC Endpoint for S3
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:SubnetId
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
#                "ec2:DescribeVpcEndpoints"
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


APPLICABLE_RESOURCES = ["AWS::EC2::SubnetId"]

log = logging.getLogger()
log.setLevel(logging.INFO)

def evaluate_compliance(configuration_item):
        if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
               }
    subnet_id   = configuration_item["configuration"]["subnetId"]
    vpc_id      = configuration_item["configuration"]["vpcId"]
    client      = boto3.client("ec2");
    s3vpcendpt  = False
    route_tables = []
    for resource_type in configuration_item["relationships"]:
        if resource_type['resourceType']=='AWS::EC2::RouteTable':
            route_table = resource_type['resourceId']
 
        
    vpcendpoints = client.describe_vpc_endpoints()
    
    for m in vpcendpoints['VpcEndpoints']:
        if m['ServiceName'].endswith('.s3') and m['State'] == 'available' and m['VpcId']== vpc_id:
            route_tables= m['RouteTableIds']
            if route_table in route_tables:
               s3vpcendpt  = "True"

    if s3vpcendpt:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": 'SubnetId '+subnet_id+ ' has a S3 VPC endpoint'
        }
    else:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : 'SubnetId '+ str(subnet_id)+ '  does not have a S3 VPC endpoint'
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
