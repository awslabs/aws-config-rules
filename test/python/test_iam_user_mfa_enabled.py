#!/usr/bin/env python
"""Tests Launch Wizard SG Attachment"""
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
import python.iam_user_mfa_enabled


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open('%s/../assets/config_events/iam_user_mfa_enabled_success.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_SUCCESS = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/iam_user_mfa_enabled_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_FAILURE = json.load(json_data)
    json_data.close()

with open('%s/../assets/aws_api/iam_list_mfa_devices.json' % BASE_DIR) as json_data:
    IAM_LIST_MFA_DEVICES = json.load(json_data)
    json_data.close()


class TestIamUserMfaEnabled(unittest.TestCase):
    """Test IAM user has MFA Enabled """

    def test_iam_user_mfa_success(self):
        """Test success"""
        config = boto3.client('config')
        stubber_config = Stubber(config)
        iam = boto3.client('iam')
        stubber_iam = Stubber(iam)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'The user has MFA enabled.',
                    'ComplianceResourceId': 'AIDAIEJCNPAE4EONMASRY',
                    'ComplianceResourceType': 'AWS::IAM::User',
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': '2017-07-27T20:07:35.770Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        describe_route_request = {'UserName': 'Bob'}

        stubber_config.add_response('put_evaluations', {}, config_request)
        stubber_iam.add_response('list_mfa_devices', IAM_LIST_MFA_DEVICES, describe_route_request)

        with patch('python.iam_user_mfa_enabled.AWS_CONFIG', config):
            with patch('python.iam_user_mfa_enabled.AWS_IAM', iam):
                with stubber_config:
                    with stubber_iam:
                        python.iam_user_mfa_enabled.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

    def test_iam_user_mfa_failure(self):
        """Test a failing item"""
        config = boto3.client('config')
        stubber_config = Stubber(config)
        iam = boto3.client('iam')
        stubber_iam = Stubber(iam)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'The user does not have MFA enabled.',
                    'ComplianceResourceId': 'AIDAIEJCNPAE4EONMASRY',
                    'ComplianceResourceType': 'AWS::IAM::User',
                    'ComplianceType': 'NON_COMPLIANT',
                    'OrderingTimestamp': '2017-07-27T20:07:35.770Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        list_mfa_devices_request = {'UserName': 'Jason'}
        list_mfa_devices_response = {'MFADevices': []}
        get_login_profile_response = {
            'LoginProfile': {
                'UserName': 'string',
                'CreateDate': '2015-06-16T22:36:37',
                'PasswordResetRequired': False
            }
        }
        get_login_profile_request = {'UserName': 'Jason'}

        stubber_config.add_response('put_evaluations', {}, config_request)
        stubber_iam.add_response('list_mfa_devices', list_mfa_devices_response, list_mfa_devices_request)
        stubber_iam.add_response('get_login_profile', get_login_profile_response, get_login_profile_request)

        with patch('python.iam_user_mfa_enabled.AWS_CONFIG', config):
            with patch('python.iam_user_mfa_enabled.AWS_IAM', iam):
                with stubber_config:
                    with stubber_iam:
                        python.iam_user_mfa_enabled.lambda_handler(CANNED_CONFIG_EVENT_FAILURE, {})


if __name__ == '__main__':
    unittest.main()
