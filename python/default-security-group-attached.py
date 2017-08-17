
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
# 
# Description: Check that default security groups are not attached to EC2,RDS,ELB.
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:NetworkInterfaces
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
#                "ec2:DescribeNetworkInterfaces"
#            ],
#            "Resource": "*"
#        }
#    ]
#}


import boto3
import json

APPLICABLE_RESOURCES = ["AWS::EC2::NetworkInterfaces"]

def lambda_handler(event, context):

    is_compliant = True
    invoking_event = json.loads(event['invokingEvent'])
    private_ip =''
    annotation = ''

    network_interface_id = invoking_event['configurationItem']['resourceId']
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
               }
    
    

    network_interfaces = boto3.client('ec2').describe_network_interfaces()
    
    
    for i in network_interfaces['NetworkInterfaces']:
        if i['NetworkInterfaceId'] == network_interface_id:
            private_ip = i['PrivateIpAddress']
            for j in i['Groups']:
                if j['GroupName'] == 'default':
                    annotation = annotation + 'The default security group is attached to '+private_ip
                    is_compliant = False


    evaluations = [
            {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId': network_interface_id,
               'ComplianceType': 'COMPLIANT' if is_compliant else 'NON_COMPLIANT',
               'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
            }
        ]

    if annotation: evaluations[0]['Annotation'] = annotation
    response = boto3.client('config').put_evaluations(
           Evaluations = evaluations,
           ResultToken = event['resultToken'])
