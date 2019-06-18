import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import json
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::RDS::DBInstance'

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

RULE = __import__('RDS_ENHANCED_MONITORING_ENABLED')

class ComplianceTest(unittest.TestCase):
    #scenario1
    rule_invalid_parameter = '{"monitoringInterval":"12"}'
    #scenario2,scenario5
    rule_valid_parameter = '{"monitoringInterval":"5"}'
    #scenario3
    rule_parameter_mismatch = '{"monitoringInterval":"10"}'

    valid_em_interval_configured = {
        "monitoringInterval": "5"
    }

    invalid_em_not_configured = {
        "monitoringInterval": "0"
    }

    def test_scenario_1_invalid_parameter_value(self):
        invoking_event = generate_invoking_event(self.valid_em_interval_configured)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_invalid_parameter), {})
        assert_customer_error_response(self, response, 'Invalid value for the parameter "monitoringInterval", Expected a valid integer from the list [1, 5, 10, 15, 30, 60].')

    def test_scenario_2_interval_zero(self):
        invoking_event = generate_invoking_event(self.invalid_em_not_configured)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        assert_successful_evaluation(self, response, [build_expected_response('NON_COMPLIANT', 'test-instance', annotation="Enhanced Monitoring interval for this Amazon RDS instance is not configured.")])

    def test_scenario_3_interval_mismatch(self):
        invoking_event = generate_invoking_event(self.valid_em_interval_configured)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameter_mismatch), {})
        assert_successful_evaluation(self, response, [build_expected_response('NON_COMPLIANT', 'test-instance', annotation="Enhanced Monitoring interval for this Amazon RDS instance is not set with period:10")])

    def test_scenario_4_empty_ruleparameter(self):
        invoking_event = generate_invoking_event(self.valid_em_interval_configured)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, {}), {})
        assert_successful_evaluation(self, response, [build_expected_response('COMPLIANT', 'test-instance')])

    def test_scenario_5_em_interval_match(self):
        invoking_event = generate_invoking_event(self.valid_em_interval_configured)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        assert_successful_evaluation(self, response, [build_expected_response('COMPLIANT', 'test-instance')])

####################
# Helper Functions #
####################

def generate_invoking_event(test_configuration):
    invoking_event = '{"configurationItem":{"configuration":' \
                     + json.dumps(test_configuration) \
                     + ',"configurationItemCaptureTime":"2019-04-18T08:17:52.315Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::RDS::DBInstance","resourceId":"test-instance"},"messageType":"ConfigurationItemChangeNotification"}'
    return invoking_event

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': 'test-instance',
        'configRuleArn': 'arn:aws:config:us-east-1:test-instance:config-rule/config-rule-8fngan',
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
        'accountId': 'test-instance',
        'configRuleArn': 'arn:aws:config:us-east-1:test-instance:config-rule/config-rule-8fngan',
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
