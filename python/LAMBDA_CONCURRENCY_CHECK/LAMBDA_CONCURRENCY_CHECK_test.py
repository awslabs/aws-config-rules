import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    import mock
    from mock import MagicMock
import botocore
from botocore.exceptions import ClientError

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
LAMBDA_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'sts':
            return STS_CLIENT_MOCK
        elif client_name == 'lambda':
            return LAMBDA_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('LAMBDA_CONCURRENCY_CHECK')

class SampleTest(unittest.TestCase):

    rule_parameters = '{"concurrencyLimitLow":"100", "concurrencyLimitHigh":"100"}'

    getFunctionOutputWithConcurrency = { "Concurrency": { "ReservedConcurrentExecutions": 100 } }
    getFunctionOutputWithoutConcurrency = {}

    listAllFunctions = { "Functions": [{"FunctionName": "tam"}, {"FunctionName": "glue"}] }

    invoking_event_iam_role_sample = '{ \
	"configurationItem": {    \
		"configurationItemStatus": "ResourceDiscovered",  \
		"resourceName": "tam",    \
		"ARN": "arn:aws:lambda:ap-south-1:633141505637:function:tam"  \
	},     \
	"notificationCreationTime": "2018-07-02T23:05:34.445Z",    \
	"messageType": "ConfigurationItemChangeNotification" }'

    def side_effect(self, value):
        if value == 'tam':
            return self.getFunctionOutputWithConcurrency
        else:
            return self.getFunctionOutputWithoutConcurrency

    #Scenario: 1
    def test_lambda_not_present(self):
        invoking_event_iam_role_sample = '{ \
    	"configurationItem": {    \
    		"configurationItemStatus": "ResourceDiscovered",  \
    		"resourceName": "",    \
    		"ARN": "arn:aws:lambda:ap-south-1:633141505637:function:tam"  \
    	},     \
    	"notificationCreationTime": "2018-07-02T23:05:34.445Z",    \
    	"messageType": "ConfigurationItemChangeNotification" }'

        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = {})
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_iam_role_sample, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', "", 'AWS::Lambda::Function'))
        assert_successful_evaluation(self, response, resp_expected)
    #
    #Scenario: 2
    def test_concurrency_not_set_in_lambda(self):
        invoking_event_iam_role_sample = '{ \
    	"configurationItem": {    \
    		"configurationItemStatus": "ResourceDiscovered",  \
    		"resourceName": "glue",    \
    		"ARN": "arn:aws:lambda:ap-south-1:633141505637:function:tam"  \
    	},     \
    	"notificationCreationTime": "2018-07-02T23:05:34.445Z",    \
    	"messageType": "ConfigurationItemChangeNotification" }'
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_iam_role_sample, self.rule_parameters), {})

        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'tam', 'AWS::Lambda::Function'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=2)

    #Scenario: 3
    def test_both_rule_parameters_empty(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"", "concurrencyLimitHigh":""}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})

        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'tam', 'AWS::Lambda::Function'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=2)

    #Scenario: 4
    def test_concurrencyLimitLow_set_lower_than_concurrency_concurrencyLimitHigh_not_set(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"50", "concurrencyLimitHigh":""}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})

        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'tam', 'AWS::Lambda::Function', 'concurrencyLimitHigh is not set and fuction concurrency is greater than concurrencyLimitLow'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    #Scenario: 5
    def test_concurrencyLimitLow_set_higher_than_concurrency_concurrencyLimitHigh_not_set(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"200", "concurrencyLimitHigh":""}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})

        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'tam', 'AWS::Lambda::Function'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    #Scenario: 6
    def test_concurrencyLimitHigh_set_higher_than_concurrency_concurrencyLimitLow_not_set(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"", "concurrencyLimitHigh":"200"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'tam', 'AWS::Lambda::Function', 'concurrencyLimitLow is not set and fuction concurrency is lesser than concurrencyLimitHigh'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    #Scenario: 7
    def test_concurrencyLimitHigh_set_lower_than_concurrency_concurrencyLimitLow_not_set(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"", "concurrencyLimitHigh":"50"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'tam', 'AWS::Lambda::Function'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    #Scenario: 8
    def test_concurrency_lower_than_concurrencyLimitLow_higher_than_concurrencyLimitHigh(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"100", "concurrencyLimitHigh":"200"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'tam', 'AWS::Lambda::Function'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    #Scenario: 9
    def test_concurrency_higher_than_concurrencyLimitLow_lower_than_concurrencyLimitHigh(self):
        RULE.ASSUME_ROLE_MODE = False
        LAMBDA_CLIENT_MOCK.get_function = MagicMock(side_effect = self.side_effect)
        LAMBDA_CLIENT_MOCK.list_functions = MagicMock(return_value = self.listAllFunctions)
        rule_parameters = '{"concurrencyLimitLow":"50", "concurrencyLimitHigh":"200"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'tam', 'AWS::Lambda::Function', 'Lamda function concurrency is not within bounds of concurrencyLimitLow and concurrencyLimitHigh'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'glue', 'AWS::Lambda::Function', 'Concurrency not set for the lambda function'))
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
