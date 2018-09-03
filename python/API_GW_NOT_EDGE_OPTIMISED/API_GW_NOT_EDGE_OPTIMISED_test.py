#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import sys
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::RestApi'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
apigw_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'apigateway':
            return apigw_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('API_GW_NOT_EDGE_OPTIMISED')

class ParameterTest(unittest.TestCase):
    get_rest_apis_private = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['PRIVATE']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['PRIVATE']}}]
    }

    invalid_rule_parameters = '{"ExceptionList":"apiid-1"}'

    def test_api_invalid_parameter(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_private)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.invalid_rule_parameters), {})
        assert_customer_error_response(
            self, response, 'InvalidParameterValueException', 'Invalid value in the ExceptionList: apiid-1')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"ExceptionList":"apiid1,apiid2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    get_rest_apis_private = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['PRIVATE']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['PRIVATE']}}]
    }

    get_rest_apis_regional = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['REGIONAL']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['REGIONAL']}}]
    }

    get_rest_apis_edge = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['EDGE']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['EDGE']}}]
    }

    get_rest_apis_mix_compliant_only = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['REGIONAL']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['PRIVATE']}}]
    }

    get_rest_apis_mix = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['EDGE']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['REGIONAL']}},
                  {'id': 'apiid3', 'endpointConfiguration': {'types': ['PRIVATE']}}]
    }

    get_rest_apis_multi_type = {
        'items': [{'id': 'apiid1', 'endpointConfiguration': {'types': ['EDGE', 'PRIVATE']}},
                  {'id': 'apiid2', 'endpointConfiguration': {'types': ['REGIONAL']}}]
    }

    def test_no_gw(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value={"items": []})
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_private_only_COMPLIANT(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_private)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_regional_only_COMPLIANT(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_regional)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_edge_only_NON_COMPLIANT(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_edge)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'apiid1', annotation="EDGE OPTIMIZED API Gateway is present."))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'apiid2', annotation="EDGE OPTIMIZED API Gateway is present."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_mix_COMPLIANT(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_mix_compliant_only)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_mix(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_mix)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'apiid1', annotation="EDGE OPTIMIZED API Gateway is present."))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2'))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid3'))
        assert_successful_evaluation(self, response, resp_expected, 3)

    def test_edge_exception_COMPLIANT(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_edge)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid1', annotation="API is part of exception list."))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2', annotation="API is part of exception list."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_mix_with_exceptions(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_mix)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid1', annotation="API is part of exception list."))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2', annotation="API is part of exception list."))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid3'))
        assert_successful_evaluation(self, response, resp_expected, 3)

    def test_multi_type(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_apis_multi_type)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'apiid1', annotation="EDGE OPTIMIZED API Gateway is present."))
        resp_expected.append(build_expected_response('COMPLIANT', 'apiid2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

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

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                testClass.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(testClass, response, customerErrorCode=None, customerErrorMessage=None):
    if customerErrorCode:
        testClass.assertEqual(customerErrorCode, response['customerErrorCode'])
    if customerErrorMessage:
        testClass.assertEqual(customerErrorMessage, response['customerErrorMessage'])
    testClass.assertTrue(response['customerErrorCode'])
    testClass.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        testClass.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        testClass.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    sts_client_mock.reset_mock(return_value=True)
    sts_client_mock.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
