#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#

import boto3
import json

def evaluate_compliance(config_item, vpc_id):
    if (config_item['resourceType'] != 'AWS::EC2::VPC'):
        return 'NOT_APPLICABLE'

    elif is_flow_logs_enabled(vpc_id):
        return 'COMPLIANT'
    else:
        return 'NON_COMPLIANT'

def is_flow_logs_enabled(vpc_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_flow_logs(
        Filter=[
            {
                'Name': 'resource-id',
                'Values': [
                    vpc_id,
                ]
            },
        ],
    )
    if len(response[u'FlowLogs']) != 0: return True

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])

    compliance_value = 'NOT_APPLICABLE'

    vpc_id = invoking_event['configurationItem']['resourceId']
    compliance_value = evaluate_compliance(
        invoking_event['configurationItem'], vpc_id)

    config = boto3.client('config')
    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId': vpc_id,
               'ComplianceType': compliance_value,
               'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])
