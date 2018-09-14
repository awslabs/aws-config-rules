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
import json
from datetime import datetime, timedelta
import dateutil.parser

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

#############
# Main Code #
#############

config_client_mock = MagicMock()
iam_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_ACCESS_KEY_ROTATED')

class test_invalid_parameters(unittest.TestCase):
    def setUp(self):
        config_client_mock.reset_mock()
        iam_client_mock.reset_mock()

    invalid_user_whiteList_params = {
    "invalidEntry" : ['{"WhitelistedUserList":"12345"}',
                    '{"WhitelistedUserList":"ABCDEF12356"}',
                    '{"WhitelistedUserList":"mbjfEF12356"}',
                    '{"WhitelistedUserList":"AIDA"}',
                    '{"WhitelistedUserList":"AIDA*&903"}',
                    '{"WhitelistedUserList":"AIDA325ykvo"}',
                    '{"WhitelistedUserList":"(%$@!)"}'],
    "invalidSeparators" : ['{"WhitelistedUserList":"AIDAJYPPIFB65RVYU7CCW/AIDAJYPPIFB65RVY9IP62"}',
                    '{"WhitelistedUserList":"AIDAJYPPIFB65RVYU7CCW,,AIDAJYPPILP90RVYU7WWC"}']
    }

    invalid_expiry_params = ['{"KeyActiveTimeOutInDays":"-1"}',
    '{"KeyActiveTimeOutInDays":"9999999999"}',
    '{"KeyActiveTimeOutInDays":"5.6"}',
    '{"KeyActiveTimeOutInDays":"ABC"}',
    '{"KeyActiveTimeOutInDays":"*&^"}']

    def test_scenario2_user_whitelist_parameters_incorrect_entry(self):
        for invalid_param in self.invalid_user_whiteList_params['invalidEntry']:
            response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_param), {})
            assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_scenario2_user_whitelist_parameters_incorrect_separators(self):
        for invalid_param in self.invalid_user_whiteList_params['invalidSeparators']:
            response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_param), {})
            assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_scenario3_KeyActiveTimeOutInDays_parameters_incorrect_entry(self):
        for invalid_param in self.invalid_expiry_params:
            response = {}
            response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_param), {})
            assert_customer_error_response(self, response, 'InvalidParameterValueException')

class test_compliance(unittest.TestCase):
    def setUp(self):
        config_client_mock.reset_mock()
        iam_client_mock.reset_mock()

    user_list_empty = {"Users" : []}
    user_list_whitelist = {"Users": [{'UserId': 'AIDAJYPPIFB65RV8YYLDU','UserName': 'sampleUser1'}]}
    user_list = {"Users": [{'UserId': 'AIDAJYPPIFB65RV8YYLDU','UserName': 'sampleUser1'}, {'UserId': 'AIDAJYPPIFB65RV8YYLDV','UserName': 'sampleUser2'}]}
    
    no_access_key = {'AccessKeyMetadata': []}
    no_access_key_active = {'AccessKeyMetadata': [{'AccessKeyId': 'AKIAIPPNIMKJA2N7SJRA', 'Status': 'Inactive', 'UserName': 'sampleUser'}]}
    
    def construct_list_access_keys_response(self, age_key):
        list_access_keys_call = {}
        list_access_keys_call = {'AccessKeyMetadata': [{'AccessKeyId': 'AKIAIPPNIMKJA2N7SJRA',
            'CreateDate': datetime.utcnow().replace(tzinfo=dateutil.tz.tzutc()) - timedelta(days=age_key),
            'Status': 'Active', 'UserName': 'sampleUser'}]}
        return list_access_keys_call

    def test_scenario1_no_iam_users(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response("NOT_APPLICABLE", "123456789012", compliance_resource_type="AWS::::Account"))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario4_compliant_user_whitelist(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        response = rule.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserList":"AIDAJYPPIFB65RV8YYLDU"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDU", annotation='This user (AIDAJYPPIFB65RV8YYLDU) is whitelisted.'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario5_noncompliant_users_no_access_key(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_access_keys = MagicMock(return_value=self.no_access_key)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDU"))
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDV"))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario6_noncompliant_users_no_active_access_key(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_access_keys = MagicMock(return_value=self.no_access_key_active)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDU"))
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDV"))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario7_noncompliant_users_custom_timeout(self):
        custom_timeout = 20
        list_access_keys_response = self.construct_list_access_keys_response(90)
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_access_keys = MagicMock(return_value = list_access_keys_response)
        response = rule.lambda_handler(build_lambda_scheduled_event('{"KeyActiveTimeOutInDays":' + str(custom_timeout) + '}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("NON_COMPLIANT", "AIDAJYPPIFB65RV8YYLDU", annotation='This user (AIDAJYPPIFB65RV8YYLDU) has an expired active access key (AKIAIPPNIMKJA2N7SJRA). The key is older than 90 days. It must be no older than 20 days.'))
        resp_expected.append(build_expected_response("NON_COMPLIANT", "AIDAJYPPIFB65RV8YYLDV", annotation='This user (AIDAJYPPIFB65RV8YYLDV) has an expired active access key (AKIAIPPNIMKJA2N7SJRA). The key is older than 90 days. It must be no older than 20 days.'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario7_noncompliant_users_default_timeout(self):
        list_access_keys_response = self.construct_list_access_keys_response(120)
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_access_keys = MagicMock(return_value = list_access_keys_response)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response("NON_COMPLIANT", "AIDAJYPPIFB65RV8YYLDU", annotation='This user (AIDAJYPPIFB65RV8YYLDU) has an expired active access key (AKIAIPPNIMKJA2N7SJRA). The key is older than 120 days. It must be no older than 90 days.'))
        resp_expected.append(build_expected_response("NON_COMPLIANT", "AIDAJYPPIFB65RV8YYLDV", annotation='This user (AIDAJYPPIFB65RV8YYLDV) has an expired active access key (AKIAIPPNIMKJA2N7SJRA). The key is older than 120 days. It must be no older than 90 days.'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario8_compliant_users_default_timeout(self):
        list_access_keys_response = self.construct_list_access_keys_response(80)
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_access_keys = MagicMock(return_value = list_access_keys_response)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDU"))
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDV"))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario8_compliant_users_custom_timeout(self):
        list_access_keys_response = self.construct_list_access_keys_response(10)
        custom_timeout = 20
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_access_keys = MagicMock(return_value = list_access_keys_response)
        response = rule.lambda_handler(build_lambda_scheduled_event('{"KeyActiveTimeOutInDays":' + str(custom_timeout) + '}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDU"))
        resp_expected.append(build_expected_response("COMPLIANT", "AIDAJYPPIFB65RV8YYLDV"))
        assert_successful_evaluation(self, response, resp_expected, 2)

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    rule_parameters = json.dumps(rule_parameters)
    invoking_event = json.dumps(invoking_event)

    invoking_event = '{"awsAccountId":"825908965814","notificationCreationTime":"2018-03-01T11:21:06.236Z","messageType":"ScheduledNotification","recordVersion":"1.0"}'

    event_to_return = {'accountId': 'AIDAJYPPIFB65RV8YYLDU',
         'configRuleArn': 'arn:aws:config:ap-south-1:825908965814:config-rule/config-rule-swb7as',
         'configRuleId': 'config-rule-swb7as',
         'configRuleName': 'iam-principal-used-90-days',
         'eventLeftScope': False,
         'executionRoleArn': 'arn:aws:iam::825908965814:role/service-role/config-role-ap-south-1',
         'invokingEvent': invoking_event,
         'resultToken': 'TESTMODE',
         'valid_rule_parameters': rule_parameters,
         'version': '1.0'}
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
