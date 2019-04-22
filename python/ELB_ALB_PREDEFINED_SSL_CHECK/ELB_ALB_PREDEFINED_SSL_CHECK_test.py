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
DEFAULT_RESOURCE_TYPE = 'AWS::ElasticLoadBalancingV2::LoadBalancer'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
elbv2_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'elbv2':
            return elbv2_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('ELB_ALB_PREDEFINED_SSL_CHECK')

class TestParameter(unittest.TestCase):

    rule_parameters_empty = '{}'
    rule_parameters_one = '{"ValidPolicies":"Some_policy_1"}'
    rule_parameters_two = '{"ValidPolicies":"Some_policy_1, Some_policy_2"}'
    
    def test_validpolicy_mandatory_parameter(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'The parameter "ValidPolicies" must be configured.')

class TestCompliance(unittest.TestCase):

    rule_parameters_two = '{"ValidPolicies":"Some_policy_1, Some_policy_2"}'
    describe_listeners_no_https = {'Listeners': [{ 'ListenerArn': 'arn1'}]}
    describe_listeners_compliant = {'Listeners': [{ 'ListenerArn': 'arn1', 'SslPolicy': 'Some_policy_1'},{ 'ListenerArn': 'arn2', 'SslPolicy': 'Some_policy_2'}]}
    describe_listeners_non_compliant = {'Listeners': [{ 'ListenerArn': 'arn2', 'SslPolicy': 'Some_policy_3'}]}
    describe_load_balancers_not_app = {'LoadBalancers': [{ 'LoadBalancerArn': 'arn1', 'Type': 'other'}]}
    describe_load_balancers_app = {'LoadBalancers': [{ 'LoadBalancerArn': 'arn1', 'Type': 'application'},{ 'LoadBalancerArn': 'arn2', 'Type': 'application'}]}

    def test_scenario0_no_elb(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario0_no_app_elb(self):
        rule.ASSUME_ROLE_MODE = False
        elbv2_client_mock.describe_load_balancers = MagicMock(return_value=self.describe_load_balancers_not_app)
        elbv2_client_mock.describe_listeners = MagicMock(return_value=self.describe_listeners_no_https)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario1_no_https_listener(self):
        rule.ASSUME_ROLE_MODE = False
        elbv2_client_mock.describe_load_balancers = MagicMock(return_value=self.describe_load_balancers_app)
        elbv2_client_mock.describe_listeners = MagicMock(return_value=self.describe_listeners_no_https)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'arn1'))
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'arn2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario2_no_compliant_https(self):
        rule.ASSUME_ROLE_MODE = False
        elbv2_client_mock.describe_load_balancers = MagicMock(return_value=self.describe_load_balancers_app)
        elbv2_client_mock.describe_listeners = MagicMock(return_value=self.describe_listeners_non_compliant)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn1', annotation='This ALB has a HTTPS listener with a TLS/SSL policy (Some_policy_3) not listed in the ValidPolicies parameter (Some_policy_1, Some_policy_2).'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn2', annotation='This ALB has a HTTPS listener with a TLS/SSL policy (Some_policy_3) not listed in the ValidPolicies parameter (Some_policy_1, Some_policy_2).'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario3_compliant_https(self):
        rule.ASSUME_ROLE_MODE = False
        elbv2_client_mock.describe_load_balancers = MagicMock(return_value=self.describe_load_balancers_app)
        elbv2_client_mock.describe_listeners = MagicMock(return_value=self.describe_listeners_compliant)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'arn2'))
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

    rule_parameters_one = '{"ValidPolicies":"some_policy_1"}'

    def test_sts_unknown_error(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}', self.rule_parameters_one), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}', self.rule_parameters_one), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
