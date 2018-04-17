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
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
import python.cloudtrail_encrypted


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open('%s/../assets/config_events/cloudtrail_encrypted_success.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_SUCCESS = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/cloudtrail_encrypted_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_FAILURE = json.load(json_data)
    json_data.close()


class TesetCloudTrailEncrypted(unittest.TestCase):
    """Test CloudTrail Encrypted"""

    def test_ct_encrypted_success(self):
        "Test creating a bucket"
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'COMPLIANT',
                    'Annotation': 'Encryption is enabled (no key specified in '
                                  'the Rule).',
                    'ComplianceResourceType': 'AWS::CloudTrail::Trail',
                    'ComplianceResourceId': 'Test',
                    'OrderingTimestamp': '2018-02-11T02:34:43.438Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        CANNED_CONFIG_EVENT_SUCCESS['ruleParameters'] = "{}"
        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.cloudtrail_encrypted.AWS_CONFIG', config):
            with stubber_config:
                python.cloudtrail_encrypted.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

    def test_ct_encrypt_params_success(self):
        """Test CloudTrail Encrypted with Parameters"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'COMPLIANT',
                    'Annotation': 'Encryption is enabled with the specified KMS '
                                  'key '
                                  '[arn:aws:kms:us-east-1:123456789012:key/d235821b-47e7-41e3-a1ae-80ed225d2466].',
                    'ComplianceResourceType': 'AWS::CloudTrail::Trail',
                    'ComplianceResourceId': 'Test',
                    'OrderingTimestamp': '2018-02-11T02:34:43.438Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        CANNED_CONFIG_EVENT_SUCCESS['ruleParameters'] = "{\"KmsKeyArn\":\"arn:aws:kms:us-east-1:123456789012:key/d235821b-47e7-41e3-a1ae-80ed225d2466\"}"
        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.cloudtrail_encrypted.AWS_CONFIG', config):
            with stubber_config:
                python.cloudtrail_encrypted.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})


    def test_ct_encrypted_failure(self):
        """Test CloudTrail Encrypted Failure"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': 'Encryption is disabled.',
                    'ComplianceResourceType': 'AWS::CloudTrail::Trail',
                    'ComplianceResourceId': 'Test',
                    'OrderingTimestamp': '2018-02-11T02:34:43.438Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        CANNED_CONFIG_EVENT_SUCCESS['ruleParameters'] = "{}"
        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.cloudtrail_encrypted.AWS_CONFIG', config):
            with stubber_config:
                python.cloudtrail_encrypted.lambda_handler(CANNED_CONFIG_EVENT_FAILURE, {})

    def test_ct_encrypt_params_failure(self):
        """Test CloudTrail Encrypted With Parameters Failure"""
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': 'Encryption is enabled with '
                                  '[arn:aws:kms:us-east-1:123456789012:key/d235821b-47e7-41e3-a1ae-80ed225d2466]. '
                                  'It is not with the specified KMS key in the '
                                  'rule '
                                  '[arn:aws:kms:us-east-1:123456789012:key/a123456b-12a3-12a1-a1bc-12ab345c678].',
                    'ComplianceResourceType': 'AWS::CloudTrail::Trail',
                    'ComplianceResourceId': 'Test',
                    'OrderingTimestamp': '2018-02-11T02:34:43.438Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        CANNED_CONFIG_EVENT_SUCCESS['ruleParameters'] = "{\"KmsKeyArn\":\"arn:aws:kms:us-east-1:123456789012:key/a123456b-12a3-12a1-a1bc-12ab345c678\"}"
        stubber_config.add_response('put_evaluations', {}, config_request)
        with patch('python.cloudtrail_encrypted.AWS_CONFIG', config):
            with stubber_config:
                python.cloudtrail_encrypted.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

if __name__ == '__main__':
    unittest.main()
