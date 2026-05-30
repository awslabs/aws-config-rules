import sys
import unittest
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::CloudFront::Distribution'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
CLOUDFRONT_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'cloudfront':
            return CLOUDFRONT_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('CLOUDFRONT_PREDEFINED_SSL_CHECK')

class ParameterTest(unittest.TestCase):

    rule_parameters_empty = '{}'
    rule_parameters_one = '{"ValidPolicies":"Some_policy_1"}'
    rule_parameters_two = '{"ValidPolicies":"Some_policy_1, Some_policy_2"}'

    def test_validpolicy_mandatory_parameter(self):
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'The parameter "ValidPolicies" must be configured.')

class ComplianceTest(unittest.TestCase):

    rule_parameters_two = '{"ValidPolicies":"Some_policy_1, Some_policy_2"}'
    describe_distributions_compliant = {
        'DistributionList': {
            'Items': [
                {'Id': 'id1', 'ViewerCertificate': {'MinimumProtocolVersion': 'Some_policy_1'}},
                {'Id': 'id2', 'ViewerCertificate': {'MinimumProtocolVersion': 'Some_policy_2'}},
            ],
        },
    }
    describe_distributions_non_compliant = {
        'DistributionList': {
            'Items': [
                {'Id': 'id1', 'ViewerCertificate': {'MinimumProtocolVersion': 'Some_policy_3'}},
            ],
        },
    }

    def test_scenario0_no_distributions(self):
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario1_no_compliant_https(self):
        RULE.ASSUME_ROLE_MODE = False
        CLOUDFRONT_CLIENT_MOCK.list_distributions = MagicMock(return_value=self.describe_distributions_non_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'id1', annotation='This CloudFront Distribution has a TLS/SSL policy (Some_policy_3) not listed in the ValidPolicies parameter (Some_policy_1, Some_policy_2).'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario2_compliant_https(self):
        RULE.ASSUME_ROLE_MODE = False
        CLOUDFRONT_CLIENT_MOCK.list_distributions = MagicMock(return_value=self.describe_distributions_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_two), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'id1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'id2'))
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

    rule_parameters_one = '{"ValidPolicies":"some_policy_1"}'

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}', self.rule_parameters_one), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}', self.rule_parameters_one), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
