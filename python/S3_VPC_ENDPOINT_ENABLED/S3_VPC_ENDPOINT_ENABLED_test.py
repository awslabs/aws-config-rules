# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore


##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::VPC'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EC2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'ec2':
            return EC2_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('S3_VPC_ENDPOINT_ENABLED')

class ComplianceTest(unittest.TestCase):
     # Unit test for no VPC is present -- GHERKIN Scenario 1
    def test_scenario_1(self):
        EC2_CLIENT_MOCK.reset_mock()
        describevpc_return = {"Vpcs":[]}
        EC2_CLIENT_MOCK.describe_vpcs = MagicMock(return_value=describevpc_return)
        resp_expected = []
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', compliance_resource_type='AWS::EC2::VPC'))
        assert_successful_evaluation(self, response, resp_expected)

    #Unit test for VPC is present and no AWS S3 VPC endpoints are present for that VPC -- GHERKIN Scenario 2
    def test_scenario_2(self):
        EC2_CLIENT_MOCK.reset_mock()
        vpc_id = "vpc-1234567"
        describevpc_return = {"Vpcs":[{"VpcId":vpc_id}]}
        EC2_CLIENT_MOCK.describe_vpcs = MagicMock(return_value=describevpc_return)
        describevpcendpoints_return = {"VpcEndpoints":[]}
        EC2_CLIENT_MOCK.describe_vpc_endpoints = MagicMock(return_value=describevpcendpoints_return)
        resp_expected = []
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'vpc-1234567', compliance_resource_type='AWS::EC2::VPC', annotation='There are no Amazon S3 VPC endpoints present in '+ vpc_id+'.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Unit test for when Amazon VPC has a AWS S3 VPC present but is not in available state -- Gherkin Scenario 3
    def test_scenario_3(self):
        EC2_CLIENT_MOCK.reset_mock()
        resp_expected = []
        vpc_id = "vpc-1234567"
        vpc_return = {'Vpcs':[{'VpcId':'vpc-1234567'}]}
        EC2_CLIENT_MOCK.describe_vpcs = MagicMock(return_value=vpc_return)
        describevpcendpoints_return = {
            "VpcEndpoints": [
                {
                    "VpcEndpointId": "vpce-06e48c97f0bc5d501",
                    "VpcEndpointType": "Gateway",
                    "VpcId": "vpc-0056487b",
                    "ServiceName": "com.amazonaws.us-east-1.s3",
                    "State": "pending",
                    "PolicyDocument": "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
                    "RouteTableIds": [
                        "rtb-0ba1ba4f40636b1fd"
                    ]
                }
            ]
        }
        EC2_CLIENT_MOCK.describe_vpc_endpoints = MagicMock(return_value=describevpcendpoints_return)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'vpc-1234567', compliance_resource_type='AWS::EC2::VPC', annotation='The Amazon S3 VPC endpoint is not in Available state '+vpc_id+'.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Unit test for VPC is present, and S3 endpoint is present in available state -- Gherkin Scenario 4
    def test_scenario_4(self):
        EC2_CLIENT_MOCK.reset_mock()
        resp_expected = []
        vpc_return = {'Vpcs':[{'VpcId':'vpc-1234567'}]}
        EC2_CLIENT_MOCK.describe_vpcs = MagicMock(return_value=vpc_return)
        describevpcendpoints_return = {
            "VpcEndpoints": [
                {
                    "VpcEndpointId": "vpce-06e48c97f0bc5d501",
                    "VpcEndpointType": "Gateway",
                    "VpcId": "vpc-0056487b",
                    "ServiceName": "com.amazonaws.us-east-1.s3",
                    "State": "available",
                    "PolicyDocument": "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}",
                    "RouteTableIds": [
                        "rtb-0ba1ba4f40636b1fd"
                    ]
                },
                {
                    "VpcEndpointId": "vpce-03ff48d1f2709aa88",
                    "VpcEndpointType": "Interface",
                    "VpcId": "vpc-0056487b",
                    "ServiceName": "com.amazonaws.us-east-1.secretsmanager",
                    "State": "available",
                    "PolicyDocument": "{\n  \"Statement\": [\n    {\n      \"Action\": \"*\", \n      \"Effect\": \"Allow\", \n      \"Principal\": \"*\", \n      \"Resource\": \"*\"\n    }\n  ]\n}",
                    "RouteTableIds": [],
                    "SubnetIds": [
                        "subnet-711b7d3b"
                    ]
                }
            ]
        }
        EC2_CLIENT_MOCK.describe_vpc_endpoints = MagicMock(return_value=describevpcendpoints_return)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected.append(build_expected_response('COMPLIANT', 'vpc-1234567', compliance_resource_type='AWS::EC2::VPC'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response['customerErrorMessage'])
    test_class.assertTrue(response['customerErrorCode'])
    test_class.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
