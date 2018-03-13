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
    subnet_ids   = []
    for i in configuration_item["configuration"]['dBSubnetGroup']['subnets']:
        subnet_ids.append(i['subnetIdentifier'])
    client      = boto3.client("ec2");

    response    = client.describe_route_tables()

    # If the subnet is explicitly associated to a route table, check if there
    # is a public route. If no explicit association exists, check if the main
    # route table has a public route.

    private = True

    for subnet_id in subnet_ids:
        mainTableIsPublic = False
        noExplicitAssociationFound = True
        explicitAssocationIsPublic = False
        for i in response['RouteTables']:
            if i['VpcId'] == vpc_id:
                for j in i['Associations']:
                    if j['Main'] == True:
                        for k in i['Routes']:
                            if k['DestinationCidrBlock'] == '0.0.0.0/0' or k['GatewayId'].startswith('igw-'):
                                mainTableIsPublic = True
                    else:
                        if j['SubnetId'] == subnet_id:
                            noExplicitAssociationFound = False
                            for k in i['Routes']:
                                if k['DestinationCidrBlock'] == '0.0.0.0/0' or k['GatewayId'].startswith('igw-'):
                                    explicitAssocationIsPublic = True

        if (mainTableIsPublic and noExplicitAssociationFound) or explicitAssocationIsPublic:
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
