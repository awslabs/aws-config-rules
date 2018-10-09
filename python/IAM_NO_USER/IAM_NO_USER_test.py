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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
iam_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_NO_USER')

#Scenario 2
class TestInvalidParameters(unittest.TestCase):
    invalid_params_numeric_user_id = '{"WhitelistUserList":"12345"}'
    invalid_params_malformed_user_id = '{"WhitelistUserList":"ABCDEF12356"}'
    invalid_params_invalid_lowercase_user_id = '{"WhitelistUserList":"mbjfEF12356"}'
    invalid_params_short_user_id = '{"WhitelistUserList":"AIDA"}'
    invalid_params_disallowed_symbols_in_user_id = '{"WhitelistUserList":"AIDA*&903"}'
    invalid_params_space_in_user_id = '{"WhitelistUserList":"AIDA 2356ACBG"}'
    invalid_params_lowercase_user_id = '{"WhitelistUserList":"AIDA325ykvo"}'
    invalid_params_all_symbols_user_id = '{"WhitelistUserList":"(%$@!)"}'
    invalid_params_space_seperator = '{"WhitelistUserList":"AIDAJYPPIFB65RVYU7CCW AIDAJYPPIFB65RVYU7AAD"}'
    invalid_params_slash_separator = '{"WhitelistUserList":"AIDAJYPPIFB65RVYU7CCW/AIDAJYPPIFB65RVY9IP62"}'
    invalid_params_double_comma_separator = '{"WhitelistUserList":"AIDAJYPPIFB65RVYU7CCW,,AIDAJYPPILP90RVYU7WWC"}'

    def setUp(self):
        config_client_mock.reset_mock()
        iam_client_mock.reset_mock()

    def test_invalid_params_numeric_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_numeric_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_malformed_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_malformed_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_invalid_lowercase_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_invalid_lowercase_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_short_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_short_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_disallowed_symbols_in_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_disallowed_symbols_in_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_space_in_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_space_in_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_lowercase_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_lowercase_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_all_symbols_user_id(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_all_symbols_user_id),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_space_seperator(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_space_seperator),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_slash_separator(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_slash_separator),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_params_double_comma_separator(self):
        response = rule.lambda_handler(
            build_lambda_scheduled_event(self.invalid_params_double_comma_separator),
            {}
        )
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

class TestScheduledExecution(unittest.TestCase):

    valid_params = '{"WhitelistUserList":"AIDAJYPPIFB65RVYU7CCW"}'

    list_users_no_results = {"Users": []}
    list_users_whitelisted_result_only = {"Users": [{"UserName": "some-user-name", "UserId":"AIDAJYPPIFB65RVYU7CCW"}]}
    list_users_mixed_whitelisted_result = {
        "Users": [
            {"UserName": "some-user-name-1", "UserId":"AIDAJYPPIFB65RVYU7CCW"},
            {"UserName": "some-user-name-2", "UserId":"AIDAJYPPIFB65RVYU7CCZ"}
        ]
    }

    def setUp(self):
        config_client_mock.reset_mock()
        iam_client_mock.reset_mock()
        rule.ASSUME_ROLE_MODE = False

    #Scenario 1
    def test_no_iam_users(self):
        iam_client_mock.list_users = MagicMock(return_value=self.list_users_no_results)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params),{})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                '123456789012',
                'AWS::::Account'
            )
        )

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3
    def test_whitelisted_users_only(self):
        iam_client_mock.list_users = MagicMock(
            return_value=self.list_users_whitelisted_result_only
        )
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params),{})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                '123456789012',
                'AWS::::Account'
            )
        )

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 4
    def test_mixed_whitelisted_users(self):
        iam_client_mock.list_users = MagicMock(
            return_value=self.list_users_mixed_whitelisted_result
        )
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params),{})

        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                '123456789012',
                'AWS::::Account',
                'The user (some-user-name-2) with id (AIDAJYPPIFB65RVYU7CCZ) is not in the whitelist.'
            )
        )
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
