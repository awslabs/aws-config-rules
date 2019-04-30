#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import sys
import json
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
DEFAULT_RESOURCE_TYPE = 'AWS::CloudFront::Distribution'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        if client_name == 'sts':
            return sts_client_mock
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('CLOUDFRONT_LOGGING_ENABLED')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{\"CentralLoggingBucket\": \"cloudfront-logs-bucket-here\"}'

    def setUp(self):
        pass

    cf_distribution_log_disabled = {
        "configuration": {
            "distributionConfig": {
                "logging": {
                    "bucket": "",
                    "enabled": False
                },
            },
        },
        "ARN":"arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6",
        "configurationItemCaptureTime": "2018-11-10T08:22:15.826Z",
        "awsAccountId": "123456789012",
        "configurationItemStatus": "ResourceDiscovered",
        "resourceType": "AWS::CloudFront::Distribution",
        "resourceId": "arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6",
        "resourceName": "CFDistribution"
    }

    cf_distribution_log_enabled = {
        "configuration": {
            "distributionConfig": {
                "logging": {
                    "bucket":"cloudfront-logs-bucket-here" + '.s3.amazonaws.com',
                    "enabled": True
                },
            },
        },
        "ARN":"arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6",
        "configurationItemCaptureTime": "2018-11-10T08:22:15.826Z",
        "awsAccountId": "123456789012",
        "configurationItemStatus": "ResourceDiscovered",
        "resourceType": "AWS::CloudFront::Distribution",
        "resourceId": "arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6",
        "resourceName": "CFDistribution"
    }

    cf_distribution_log_enabled_wrong_bucket = {
        "configuration": {
            "distributionConfig": {
                "logging": {
                    "bucket":"im-different-bucket" + '.s3.amazonaws.com',
                    "enabled": True
                },
            },
        },
        "ARN":"arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6",
        "configurationItemCaptureTime": "2018-11-10T08:22:15.826Z",
        "awsAccountId": "123456789012",
        "configurationItemStatus": "ResourceDiscovered",
        "resourceType": "AWS::CloudFront::Distribution",
        "resourceId": "arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6",
        "resourceName": "CFDistribution"
    }

    def test_cf_distribution_log_enabled(self):
        invoking_event = '{"awsAccountId":"123456789012","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(self.cf_distribution_log_enabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6', 'AWS::CloudFront::Distribution'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_cf_distribution_log_disabled(self):
        resp_expected = []
        invoking_event = '{"awsAccountId":"123456789012","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(self.cf_distribution_log_disabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6', 'AWS::CloudFront::Distribution', 'Distribution is not configured to store logs.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_cf_distribution_log_enabled_wrong_bucket(self):
        invoking_event = '{"awsAccountId":"123456789012","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(self.cf_distribution_log_enabled_wrong_bucket)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:cloudfront::123456789012:distribution/E1NFJOWF2FZVA6', 'AWS::CloudFront::Distribution', 'Distribution is configured to store logs in an unauthorized bucket.'))
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

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
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
        rule.evaluate_parameters = MagicMock(return_value=True)
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        rule.evaluate_parameters = MagicMock(return_value=True)
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
