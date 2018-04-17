#!/usr/bin/env python
"""Tests S3 Bucket Exposed"""
# pylint: disable=C0301

import unittest
import json
import os
import sys
from botocore.stub import Stubber
import boto3
from mock import patch
os.environ['AWS_REGION'] = 'us-east-1'
os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
import python.s3_bucket_exposed


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open('%s/../assets/config_events/s3_bucket_exposed_success.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_SUCCESS = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/s3_bucket_exposed_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_FAILURE = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/s3_bucket_exposed_acl_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_ACL_FAILURE = json.load(json_data)
    json_data.close()


class TestRdsVpcPublicSubnet(unittest.TestCase):
    """Test S3 Bucket Exposed"""

    def test_rds_vpc_public_success(self):
        """Test success"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'This resource is compliant with the rule.',
                    'ComplianceResourceId': 'bucket-123456789012-us-east-1',
                    'ComplianceResourceType': 'AWS::S3::Bucket',
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': '2018-02-11T14:35:00.150Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.s3_bucket_exposed.AWS_CONFIG', config):
            with stubber_config:
                python.s3_bucket_exposed.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

    def test_rds_vpc_public_failure(self):
        """Test a failing item"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'The Bucket Policy allows dangerous access',
                    'ComplianceResourceId': 'bucket-123456789012-us-east-1',
                    'ComplianceResourceType': 'AWS::S3::Bucket',
                    'ComplianceType': 'NON_COMPLIANT',
                    'OrderingTimestamp': '2018-02-11T14:35:00.150Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.s3_bucket_exposed.AWS_CONFIG', config):
            with stubber_config:
                python.s3_bucket_exposed.lambda_handler(CANNED_CONFIG_EVENT_FAILURE, {})

    def test_rds_vpc_public_acl_failure(self):
        """Test a failing ACL item"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'The Bucket ACL allows dangerous access',
                    'ComplianceResourceId': 'bucket-123456789012-us-east-1',
                    'ComplianceResourceType': 'AWS::S3::Bucket',
                    'ComplianceType': 'NON_COMPLIANT',
                    'OrderingTimestamp': '2018-02-11T14:35:00.150Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.s3_bucket_exposed.AWS_CONFIG', config):
            with stubber_config:
                python.s3_bucket_exposed.lambda_handler(CANNED_CONFIG_EVENT_ACL_FAILURE, {})


if __name__ == '__main__':
    unittest.main()
