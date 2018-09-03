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
DEFAULT_RESOURCE_TYPE = 'AWS::ElasticLoadBalancingV2::LoadBalancer'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('ELB_ALB_LOGGING_ENABLED')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{\"s3BucketName\": \"im-valid-bucket-name\"}'

    empty_rule_paramter = '{\"s3BucketName\": \"\"}'

    invalid_rule_parameter = '{\"s3BucketName\": \"-im-invalid--name.\"}'

    elb_access_log_disabled = {
        "configuration": {
            "loadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:234759432549:loadbalancer/app/tomcat/e4aac69cc24849c7",
            "dNSName": "tomcat-571096051.us-west-2.elb.amazonaws.com",
            "loadBalancerName": "tomcat",
            "type": "application"
        },
        "supplementaryConfiguration": {
            "LoadBalancerAttributes": [
                {
                    "key": "access_logs.s3.bucket",
                    "value": ""
                },
                {
                    "key": "access_logs.s3.enabled",
                    "value": "false"
                }
            ],
        },
        "configurationItemCaptureTime": "2018-07-16T08:22:15.826Z",
        "awsAccountId": "123456789012",
        "configurationItemStatus": "ResourceDiscovered",
        "resourceType": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "resourceId": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7",
        "resourceName": "tomcat",
    }

    elb_access_log_enabled = {
        "configuration": {
            "loadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:234759432549:loadbalancer/app/tomcat/e4aac69cc24849c7",
            "dNSName": "tomcat-571096051.us-west-2.elb.amazonaws.com",
            "loadBalancerName": "tomcat",
            "type": "application"
        },
        "supplementaryConfiguration": {
            "LoadBalancerAttributes": [
                {
                    "key": "access_logs.s3.bucket",
                    "value": "im-valid-bucket-name"
                },
                {
                    "key": "access_logs.s3.enabled",
                    "value": "true"
                }
            ],
        },
        "configurationItemCaptureTime": "2018-07-16T08:22:15.826Z",
        "awsAccountId": "123456789012",
        "configurationItemStatus": "ResourceDiscovered",
        "resourceType": "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "resourceId": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7",
        "resourceName": "tomcat",
    }

    def test_invalid_s3_bucket_name_in_param(self):
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(self.elb_access_log_disabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.invalid_rule_parameter), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'Invalid Bucket Name.')

    def test_access_log_disabled(self):
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(self.elb_access_log_disabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7', 'AWS::ElasticLoadBalancingV2::LoadBalancer', 'Logging is not enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_access_log_enabled(self):
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(self.elb_access_log_enabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7', 'AWS::ElasticLoadBalancingV2::LoadBalancer'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_access_log_enabled_different_bucket(self):
        elb_access_log_enabled = self.elb_access_log_enabled
        elb_access_log_enabled['supplementaryConfiguration']['LoadBalancerAttributes'][0]['value'] = 'im-different-bucket'
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(elb_access_log_enabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7', 'AWS::ElasticLoadBalancingV2::LoadBalancer', 'Logs are delivered into another S3 bucket (im-different-bucket), than requested (im-valid-bucket-name).'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_access_log_enabled_empty_param(self):
        elb_access_log_enabled = self.elb_access_log_enabled
        elb_access_log_enabled['supplementaryConfiguration']['LoadBalancerAttributes'][0]['value'] = 'im-different-bucket'
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(elb_access_log_enabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.empty_rule_paramter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7', 'AWS::ElasticLoadBalancingV2::LoadBalancer'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_access_log_enabled_no_param(self):
        elb_access_log_enabled = self.elb_access_log_enabled
        elb_access_log_enabled['supplementaryConfiguration']['LoadBalancerAttributes'][0]['value'] = 'im-different-bucket'
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(elb_access_log_enabled)+'}'
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, {}), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/tomcat/e4aac69cc24849c7', 'AWS::ElasticLoadBalancingV2::LoadBalancer'))
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
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}', '{"s3BucketName":"mys3bucket"}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}', '{"s3BucketName":"mys3bucket"}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
