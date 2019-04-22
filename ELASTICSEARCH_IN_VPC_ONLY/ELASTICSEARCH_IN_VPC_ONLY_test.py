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
DEFAULT_RESOURCE_TYPE = 'AWS::Elasticsearch::Domain'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
ES_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'es':
            return ES_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('ELASTICSEARCH_IN_VPC_ONLY')

class ComplianceTest(unittest.TestCase):

    def setUp(self):
        pass

    domain_list_empty = {'DomainNames': []}
    domain_list_2 = {'DomainNames': [
        {'DomainName': 'test-es-1'},
        {'DomainName': 'test-es-2'}]}
    domain_list_6 = {'DomainNames': [
        {'DomainName': 'test-es-1'},
        {'DomainName': 'test-es-2'},
        {'DomainName': 'test-es-3'},
        {'DomainName': 'test-es-4'},
        {'DomainName': 'test-es-5'},
        {'DomainName': 'test-es-6'}]}
    domain_list_2_non_compliant = {'DomainStatusList': [
        {'DomainName': 'test-es-1'},
        {'DomainName': 'test-es-2'}]}
    domain_list_2_compliant = {'DomainStatusList': [
        {'DomainName': 'test-es-1',
         'VPCOptions':{}},
        {'DomainName': 'test-es-2',
         'VPCOptions':{}}]}
    domain_list_6_part_1 = {'DomainStatusList': [
        {'DomainName': 'test-es-1'},
        {'DomainName': 'test-es-2',
         'VPCOptions':{}},
        {'DomainName': 'test-es-3'},
        {'DomainName': 'test-es-4'},
        {'DomainName': 'test-es-5',
         'VPCOptions':{}}]}
    domain_list_6_part_2 = {'DomainStatusList': [{'DomainName': 'test-es-6', 'VPCOptions':{}}]}

    def test_scenario_1(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.domain_list_empty)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', compliance_resource_type='AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_2(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.domain_list_2)
        ES_CLIENT_MOCK.describe_elasticsearch_domains = MagicMock(return_value=self.domain_list_2_non_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-es-1'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-es-2'))
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=2)

    def test_scenario_3(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.domain_list_2)
        ES_CLIENT_MOCK.describe_elasticsearch_domains = MagicMock(return_value=self.domain_list_2_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-es-1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'test-es-2'))
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=2)

    def test_scenario_2_and_3(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.domain_list_6)
        ES_CLIENT_MOCK.describe_elasticsearch_domains = MagicMock(side_effect=[self.domain_list_6_part_1, self.domain_list_6_part_2])
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-es-1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'test-es-2'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-es-3'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-es-4'))
        resp_expected.append(build_expected_response('COMPLIANT', 'test-es-5'))
        resp_expected.append(build_expected_response('COMPLIANT', 'test-es-6'))
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=6)

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
