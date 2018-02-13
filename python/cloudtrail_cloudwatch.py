"""
    This file made available under CC0 1.0 Universal
    (https://creativecommons.org/publicdomain/zero/1.0/legalcode)

    Ensure CloudTrail is sending to CloudWatch
    Description: Checks that tracked trails are sent to cloudWatch.

    Trigger Type: Change Triggered
    Scope of Changes: AWS::CloudTrail::Trail
    Required Parameters: None
"""

import logging
import json
import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

AWS_CONFIG = boto3.client('config')

APPLICABLE_RESOURCES = ["AWS::CloudTrail::Trail"]


def evaluate_compliance(configuration_item):
    """ Verify compliance"""
    log_group = configuration_item['configuration'].get('cloudWatchLogsLogGroupArn')
    log_role = configuration_item['configuration'].get('cloudWatchLogsRoleArn')

    if log_group and log_role:
        return {
            'compliance_type': 'COMPLIANT',
            'annotation': 'CloudTrail sending to CloudWatch.'
        }

    return {
        'compliance_type': 'NON_COMPLIANT',
        'annotation': 'CloudTrail not configured to send logs to CloudWatch.'
    }


def lambda_handler(event, _):
    """ Lambda handler """
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']

    evaluation = evaluate_compliance(configuration_item)

    result_token = "No token found."
    if 'resultToken' in event:
        result_token = event['resultToken']

    AWS_CONFIG.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': configuration_item['resourceId'],
                'ComplianceType': evaluation['compliance_type'],
                'Annotation': evaluation['annotation'],
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            },
        ],
        ResultToken=result_token
    )
