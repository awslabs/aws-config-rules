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
os.environ["AWS_REGION"] = "us-east-1"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
import python.ec2_launch_wizard_sg_prohibited


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open('%s/../assets/config_events/ec2_launch_wizard_sg_prohibited_success.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_SUCCESS = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/ec2_launch_wizard_sg_prohibited_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_FAILURE = json.load(json_data)
    json_data.close()


class TesetEc2LaunchWizardSgProhibited(unittest.TestCase):
    """Test EC2 Launch Wizard SG Prohibited"""

    def test_lw_sg_prohibited_success(self):
        "Test creating a bucket"
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'Resource is compliant.',
                    'ComplianceResourceId': 'eni-ab1c2345',
                    'ComplianceResourceType': 'AWS::EC2::NetworkInterface',
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': '2018-02-09T15:39:45.641Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.ec2_launch_wizard_sg_prohibited.AWS_CONFIG', config):
            with stubber_config:
                python.ec2_launch_wizard_sg_prohibited.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

    def test_lw_sg_prohibited_failure(self):
        "Test a failing item"
        config = boto3.client('config')
        stubber_config = Stubber(config)

        config_request = {
            'Evaluations': [
                {
                    'ComplianceType': 'NON_COMPLIANT',
                    'Annotation': 'A launch-wizard security group is attached to 172.31.83.196',
                    'ComplianceResourceType': 'AWS::EC2::NetworkInterface',
                    'ComplianceResourceId': 'eni-ab1c2345',
                    'OrderingTimestamp': '2018-02-09T15:39:45.641Z'
                },
            ],
            'ResultToken': 'myResultToken'
        }

        stubber_config.add_response('put_evaluations', {}, config_request)

        with patch('python.ec2_launch_wizard_sg_prohibited.AWS_CONFIG', config):
            with stubber_config:
                python.ec2_launch_wizard_sg_prohibited.lambda_handler(CANNED_CONFIG_EVENT_FAILURE, {})


if __name__ == '__main__':
    unittest.main()
