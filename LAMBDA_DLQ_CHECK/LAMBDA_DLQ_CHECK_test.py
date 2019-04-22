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
DEFAULT_RESOURCE_TYPE = 'AWS::Lambda::Function'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'sts':
            return STS_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('LAMBDA_DLQ_CHECK')

class SampleTest(unittest.TestCase):

    rule_empty_parameter_value = '{"dlqArn":""}'
    rule_invalid_parameter = '{"dlqArn":"arn:aws:sns:us-east-1:123456789012:mytopic, arn:aws:sss:us-east-1:123456789012:myq"}'
    rule_valid_parameter = '{"dlqArn":"arn:aws:sns:us-east-1:123456789012:mytopic, arn:aws:sqs:us-east-1:123456789012:myq"}'
    rule_parameter_mismatch = '{"dlqArn":"arn:aws:sns:us-east-1:123456789012:mytopic2, arn:aws:sqs:us-east-1:123456789012:myq2"}'

    valid_dlqarn = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
        "deadLetterConfig": "arn:aws:sns:us-east-1:123456789012:mytopic"
    }

    no_dql_configured = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function"
    }

    #scenario 1
    def test_invalid_parameter_value(self):
        invoking_event = generate_invoking_event(self.valid_dlqarn)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_invalid_parameter), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException',
                                       'Invalid value for the parameter "dlqArn", Expected Comma-separated list of '
                                       'valid SQS or SNS ARNs\'s')

    #scenario 4
    def test_empty_parameter_value(self):
        invoking_event = generate_invoking_event(self.valid_dlqarn)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_empty_parameter_value), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012', 'AWS::Lambda::Function'))
        assert_successful_evaluation(self, response, resp_expected)

    #scenario 3
    def test_no_dlq_configured(self):
        invoking_event = generate_invoking_event(self.no_dql_configured)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::Lambda::Function',
                                                     'This Lambda function is not configured for DLQ'))
        assert_successful_evaluation(self, response, resp_expected)

    #scenario 5
    def test_no_dlq_match(self):
        invoking_event = generate_invoking_event(self.valid_dlqarn)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameter_mismatch), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::Lambda::Function',
                                                     'This Lambda Function is not associated with the DLQ specified in the "dlqArn" input parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    #scenario 6
    def test_dlq_match(self):
        invoking_event = generate_invoking_event(self.valid_dlqarn)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012', 'AWS::Lambda::Function'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################

def generate_invoking_event(test_configuration):
    invoking_event = '{"configurationItem":{"configuration":' \
    + json.dumps(test_configuration) \
    + ',"configurationItemCaptureTime":"2019-04-18T08:17:52.315Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::Lambda::Function","resourceId":"123456789012"},"messageType":"ConfigurationItemChangeNotification"}'
    return invoking_event

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
