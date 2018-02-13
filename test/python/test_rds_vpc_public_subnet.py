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
import python.rds_vpc_public_subnet


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

with open('%s/../assets/config_events/rds_vpc_public_subnet_success.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_SUCCESS = json.load(json_data)
    json_data.close()

with open('%s/../assets/config_events/rds_vpc_public_subnet_failure.json' % BASE_DIR) as json_data:
    CANNED_CONFIG_EVENT_FAILURE = json.load(json_data)
    json_data.close()

with open('%s/../assets/aws_api/ec2_describe_route_tables.json' % BASE_DIR) as json_data:
    DESCRIBE_ROUTE_TABLES = json.load(json_data)
    json_data.close()


class TestRdsVpcPublicSubnet(unittest.TestCase):
    """Test RDS Instances in VPC Public Subnet"""

    def test_rds_vpc_public_success(self):
        """Test success"""
        config = boto3.client('config')
        stubber_config = Stubber(config)
        ec2 = boto3.client('ec2')
        stubber_ec2 = Stubber(ec2)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'Its in private subnet',
                    'ComplianceResourceId': 'db-MHEGTMFH4QCW4XPXTCVQ2BOMMQ',
                    'ComplianceResourceType': 'AWS::RDS::DBInstance',
                    'ComplianceType': 'COMPLIANT',
                    'OrderingTimestamp': '2018-02-09T20:12:28.245Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        describe_route_request = {'Filters': [{'Name': 'vpc-id', 'Values': ['vpc-a01106c2']}]}

        stubber_config.add_response('put_evaluations', {}, config_request)
        stubber_ec2.add_response('describe_route_tables', DESCRIBE_ROUTE_TABLES, describe_route_request)

        with patch('python.rds_vpc_public_subnet.AWS_CONFIG', config):
            with patch('python.rds_vpc_public_subnet.AWS_EC2', ec2):
                with stubber_config:
                    with stubber_ec2:
                        python.rds_vpc_public_subnet.lambda_handler(CANNED_CONFIG_EVENT_SUCCESS, {})

    def test_rds_vpc_public_failure(self):
        """Test a failing item"""
        config = boto3.client('config')
        stubber_config = Stubber(config)
        ec2 = boto3.client('ec2')
        stubber_ec2 = Stubber(ec2)

        config_request = {
            'Evaluations': [
                {
                    'Annotation': 'Not in private subnet',
                    'ComplianceResourceId': 'db-MHEGTMFH4QCW4XPXTCVQ2BOMMQ',
                    'ComplianceResourceType': 'AWS::RDS::DBInstance',
                    'ComplianceType': 'NON_COMPLIANT',
                    'OrderingTimestamp': '2018-02-09T20:12:28.245Z'
                }
            ],
            'ResultToken': 'myResultToken'
        }

        describe_route_request = {'Filters': [{'Name': 'vpc-id', 'Values': ['vpc-a01106c2']}]}

        stubber_config.add_response('put_evaluations', {}, config_request)
        stubber_ec2.add_response('describe_route_tables', DESCRIBE_ROUTE_TABLES, describe_route_request)

        with patch('python.rds_vpc_public_subnet.AWS_CONFIG', config):
            with patch('python.rds_vpc_public_subnet.AWS_EC2', ec2):
                with stubber_config:
                    with stubber_ec2:
                        python.rds_vpc_public_subnet.lambda_handler(CANNED_CONFIG_EVENT_FAILURE, {})


if __name__ == '__main__':
    unittest.main()
