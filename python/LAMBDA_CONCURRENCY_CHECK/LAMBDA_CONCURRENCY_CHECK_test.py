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
DEFAULT_RESOURCE_TYPE = 'AWS::Lambda::Function'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('LAMBDA_CONCURRENCY_CHECK')

def create_invoking_event(concurrency=None):
    if concurrency:
        return '{"messageType": "ConfigurationItemChangeNotification",\
                         "configurationItem": {"resourceType": "AWS::Lambda::Function",\
                         "resourceId": "ABC",\
                         "configurationItemCaptureTime": "2019-04-18T08:49:09.878Z",\
                         "supplementaryConfiguration": {"Concurrency":\
                         {"reservedConcurrentExecutions": ' + str(concurrency) + '}}, "configurationItemStatus": "OK"}}'
    return '{"messageType": "ConfigurationItemChangeNotification",\
                         "configurationItem": {"resourceType": "AWS::Lambda::Function",\
                         "resourceId": "ABC",\
                         "configurationItemCaptureTime": "2019-04-18T08:49:09.878Z",\
                         "supplementaryConfiguration": {}, "configurationItemStatus": "OK"}}'

class ErrorTest(unittest.TestCase):
    def test_scenario_1_invalid_parameter_value_error(self):
        invoking_event = '{"configurationItem": {"configuration": {"functionName": "ASDFGV"}}}'
        rule_parameters = '{"ConcurrencyLimitLow": "0"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        assert_customer_error_response(
            self,
            lambda_result,
            customer_error_message='ConcurrencyLimitLow must be a positive integer greater than 0.',
            customer_error_code='InvalidParameterValueException'
            )

    def test_scenario_2_concurrencylimithigh_smaller_then_concurrencylimitlow_parameter_error(self):
        invoking_event = '{"configurationItem": {"configuration": {"functionName": "ASDFGV"}}}'
        rule_parameters = '{"ConcurrencyLimitLow": "200", "ConcurrencyLimitHigh": "100"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        assert_customer_error_response(
            self,
            lambda_result,
            customer_error_message='ConcurrencyLimitHigh can not be smaller then ConcurrencyLimitLow.',
            customer_error_code='InvalidParameterValueException'
            )

class CompliantResourceTest(unittest.TestCase):

    def test_scenario_4_concurrency_set_without_parameters_c(self):
        invoking_event = create_invoking_event(200)
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=None), {})
        expected_response = build_expected_response('COMPLIANT', 'ABC')
        assert_successful_evaluation(self, lambda_result, [expected_response])

    def test_scenario_6_concurrency_set_with_concurrencylimitlow_parameter_c(self):
        invoking_event = create_invoking_event(400)
        rule_parameters = '{"ConcurrencyLimitLow": "300"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        expected_response = build_expected_response('COMPLIANT', 'ABC')
        assert_successful_evaluation(self, lambda_result, [expected_response])

    def test_scenario_8_concurrency_set_with_concurrencylimithigh_parameter_c(self):
        invoking_event = create_invoking_event(200)
        rule_parameters = '{"ConcurrencyLimitHigh": "300"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        expected_response = build_expected_response('COMPLIANT', 'ABC')
        assert_successful_evaluation(self, lambda_result, [expected_response])

    def test_scenario_9_concurrency_set_with_concurrencylimithigh_and_concurrencylimitlow_parameters_c(self):
        invoking_event = create_invoking_event(600)
        rule_parameters = '{"ConcurrencyLimitHigh": "600", "ConcurrencyLimitLow": "300"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        expected_response = build_expected_response('COMPLIANT', 'ABC')
        assert_successful_evaluation(self, lambda_result, [expected_response])

class NonCompliantResourceTest(unittest.TestCase):

    def test_scenario_3_concurrency_not_configured_nc(self):
        invoking_event = create_invoking_event()
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=None), {})
        expected_response = build_expected_response('NON_COMPLIANT', 'ABC',
                                                    annotation='Concurrency is not set for the AWS Lambda function.'
                                                    )
        assert_successful_evaluation(self, lambda_result, [expected_response])

    def test_scenario_5_concurrency_set_with_concurrencylimitlow_parameter_nc(self):
        invoking_event = create_invoking_event(200)
        rule_parameters = '{"ConcurrencyLimitLow": "300"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        expected_response = build_expected_response('NON_COMPLIANT', 'ABC',
                                                    annotation='Concurrency of the AWS Lambda function is lower than 300.')
        assert_successful_evaluation(self, lambda_result, [expected_response])

    def test_scenario_7_concurrency_set_with_concurrencylimithigh_parameter_nc(self):
        invoking_event = create_invoking_event(400)
        rule_parameters = '{"ConcurrencyLimitHigh": "300"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        expected_response = build_expected_response('NON_COMPLIANT', 'ABC',
                                                    annotation='Concurrency of the AWS Lambda function is higher than 300.')
        assert_successful_evaluation(self, lambda_result, [expected_response])

    def test_scenario_9_concurrency_set_with_concurrencylimithigh_and_concurrencylimitlow_parameters_nc(self):
        invoking_event = create_invoking_event(200)
        rule_parameters = '{"ConcurrencyLimitHigh": "600", "ConcurrencyLimitLow": "300"}'
        lambda_result = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        expected_response = build_expected_response('NON_COMPLIANT', 'ABC',
                                                    annotation='Concurrency of the AWS Lambda function is not within bounds of 300 and 600.')
        assert_successful_evaluation(self, lambda_result, [expected_response])

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
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
