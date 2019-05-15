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
DEFAULT_RESOURCE_TYPE = 'AWS::ElasticLoadBalancingV2::LoadBalancer'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
ELBV2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'elbv2':
            return ELBV2_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK')

class CompliantResourceTest(unittest.TestCase):

    def test_scenario_2_compliant(self):
        ELBV2_CLIENT_MOCK.describe_load_balancers = MagicMock(
            return_value={'LoadBalancers': [{'LoadBalancerArn': 'arn1', 'Type': 'application'}]}
        )
        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [{'ListenerArn': 'arn1', 'SslPolicy': 'Some_policy_1'}, {'ListenerArn': 'arn2', 'SslPolicy': 'Some_policy_2'}]}
        )
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, [build_expected_response('COMPLIANT', 'arn1')], 1)

    def test_scenario_4_compliant(self):
        ELBV2_CLIENT_MOCK.describe_load_balancers = MagicMock(
            return_value={'LoadBalancers': [{'LoadBalancerArn': 'arn1', 'Type': 'application'}, {'LoadBalancerArn': 'arn2', 'Type': 'application'}]}
        )
        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [
                {'ListenerArn': 'arn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'ListenerArn': 'arn2', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )

        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(
            return_value={'Rules': [
                {'RuleArn': 'arn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
                {'RuleArn': 'arn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'redirect'}]},
            ]}
        )
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = [build_expected_response('COMPLIANT', 'arn1'), build_expected_response('COMPLIANT', 'arn2')]
        assert_successful_evaluation(self, response, resp_expected, 2)

class NonCompliantResourceTest(unittest.TestCase):
    def test_scenario_3_non_compliant(self):
        ELBV2_CLIENT_MOCK.describe_load_balancers = MagicMock(
            return_value={'LoadBalancers': [{'LoadBalancerArn': 'arn1', 'Type': 'application'}, {'LoadBalancerArn': 'arn2', 'Type': 'application'}]}
        )
        ELBV2_CLIENT_MOCK.describe_listeners = MagicMock(
            return_value={'Listeners': [
                {'ListenerArn': 'arn1', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTP'}, 'Type': 'other'}]},
                {'ListenerArn': 'arn2', 'DefaultActions': [{'RedirectConfig': {'Protocol': 'HTTP'}, 'Type': 'other'}]},
            ]}
        )
        ELBV2_CLIENT_MOCK.describe_rules = MagicMock(
            return_value={'Rules': [
                {'RuleArn': 'arn1', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'other'}]},
                {'RuleArn': 'arn2', 'Actions': [{'RedirectConfig': {'Protocol': 'HTTPS'}, 'Type': 'other'}]},
            ]}
        )
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn1', annotation="HTTP listener rule must have HTTP to HTTPS redirection action configured"))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn2', annotation="HTTP listener rule must have HTTP to HTTPS redirection action configured"))
        assert_successful_evaluation(self, response, resp_expected, 2)

class NotApplicableResourceTest(unittest.TestCase):
    def test_scenario_1_not_applicable(self):
        ELBV2_CLIENT_MOCK.describe_load_balancers = MagicMock(
            return_value={'LoadBalancers': [{'LoadBalancerArn': 'arn1', 'Type': 'other'}]}
        )
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, [build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account')], 1)

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
