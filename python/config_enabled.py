#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure Config is enabled
# Description: Checks that Config has been activated and if it logs to a specific bucket OR a send to a specifc SNS topic.
#
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameters: None
# Optional Parameter 1 name: s3BucketName
# Optional Parameter 1 value example: config-bucket-123456789012-ap-southeast-1
# Optional Parameter 2 name: snsTopicARN
# Optional Parameter 2 value example: arn:aws:sns:ap-southeast-1:123456789012:config-topic


import boto3
import json
from datetime import datetime

client = boto3.client('config')


def lambda_handler(event, context):
    compliance_type = 'COMPLIANT'

    today = datetime.today()
    rule_parameters = json.loads(event['ruleParameters'])

    # First check configuration recorder is created
    config_recorder_response = client.describe_configuration_recorder_status()

    if 'ConfigurationRecordersStatus' not in config_recorder_response or \
            len(config_recorder_response['ConfigurationRecordersStatus']) < 1:
        compliance_type = 'NON_COMPLIANT'

    for config_recorder in config_recorder_response['ConfigurationRecordersStatus']:
        if not config_recorder['recording']:
            compliance_type = 'NON_COMPLIANT'

    # Check that there are delivery channels and that they're mapping to the appropriate buckets
    delivery_channels_response = client.describe_delivery_channels()
    print(delivery_channels_response['DeliveryChannels'])
	
    if 'DeliveryChannels' not in delivery_channels_response or len(delivery_channels_response['DeliveryChannels']) < 1:
        compliance_type = 'NON_COMPLIANT'
		
    if 's3BucketName' in rule_parameters:
        for channel in delivery_channels_response['DeliveryChannels']:
            if channel['s3BucketName'] != rule_parameters['s3BucketName']:
                compliance_type = 'NON_COMPLIANT'

    if 'snsTopicARN' in rule_parameters:
        for channel in delivery_channels_response['DeliveryChannels']:
            if channel['snsTopicARN'] != rule_parameters['snsTopicARN']:
                compliance_type = 'NON_COMPLIANT'

    client.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': event['accountId'],
                'ComplianceType': compliance_type,
                'Annotation': 'Check if Config was enabled and also routing to the appropriate s3 bucket and sns topic',
                'OrderingTimestamp': datetime(today.year, today.month, today.day, today.hour)
            }
        ],
        ResultToken=event['resultToken']
    )
