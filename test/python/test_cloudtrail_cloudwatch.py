#!/usr/bin/env python
"""Tests CloudTrail Encrypted"""
# pylint: disable=C0301

import unittest
import json
import os
import sys
from botocore.stub import Stubber
import boto3
from mock import patch
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
import python.cloudtrail_cloudwatch


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open('%s/../assets/config_events/cloudtrail_cloudwatch_success.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_SUCCESS = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/cloudtrail_cloudwatch_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_FAILURE = json.load(json_data)
    json_data.close()


class TesetCloudTrailEncrypted(unittest.TestCase):
    """Test CloudTrail Encrypted"""

    def test_ct_cloudwatch_success(self):
        "Test creating a bucket"
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'COMPLIANT',
                    'Annotation': 'CloudTrail sending to CloudWatch.',
                    'ComplianceResourceType': 'AWS::CloudTrail::Trail',
                    'ComplianceResourceId': 'Test',
                    'OrderingTimestamp': '2018-02-11T02:34:43.438Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        CANNED_CONFIG_EVENT_SUCCESS['ruleParameters'] = "{}"
        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.cloudtrail_cloudwatch.AWS_CONFIG', config):
            with stubber_config:
                python.cloudtrail_cloudwatch.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

    def test_ct_cloudwatch_failure(self):
        """Test CloudTrail CloudWatch Failure"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': 'CloudTrail not configured to send logs to '
                                  'CloudWatch.',
                    'ComplianceResourceType': 'AWS::CloudTrail::Trail',
                    'ComplianceResourceId': 'Test',
                    'OrderingTimestamp': '2018-02-11T02:34:43.438Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.cloudtrail_cloudwatch.AWS_CONFIG', config):
            with stubber_config:
                python.cloudtrail_cloudwatch.lambda_handler(CANNED_CONFIG_EVENT_FAILURE, {})

if __name__ == '__main__':
    unittest.main()
