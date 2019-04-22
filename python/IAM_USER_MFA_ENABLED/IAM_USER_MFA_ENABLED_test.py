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

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

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
        if client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_USER_MFA_ENABLED')


class Scenario_TestDeletedUser(unittest.TestCase):

    def test_user_is_deleted(self):
        user_list = {'Users': [
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XM',
             'UserName': 'user-name-1'},
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XN',
             'UserName': 'user-name-2'}]}
        iam_client_mock.list_users = MagicMock(return_value=user_list)
        iam_client_mock.list_mfa_devices = MagicMock(return_value={"MFADevices":[]})
        old_eval = {'EvaluationResults': [
            {'EvaluationResultIdentifier': {'EvaluationResultQualifier': {'ResourceId': 'AIDAIDFOUX2OSRO6DO7XL'}}},
            {'EvaluationResultIdentifier': {'EvaluationResultQualifier': {'ResourceId': 'AIDAIDFOUX2OSRO6DO7XM'}}}]}
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=old_eval)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'AIDAIDFOUX2OSRO6DO7XL'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM', annotation='The user (user-name-1) has no MFA Device detected.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN', annotation='The user (user-name-2) has no MFA Device detected.'))
        assert_successful_evaluation(self, response, resp_expected, 3)
    
    def test_no_user(self):
        user_list = {'Users': []}
        iam_client_mock.list_users = MagicMock(return_value=user_list)
        old_eval = {'EvaluationResults': [
            {'EvaluationResultIdentifier': {'EvaluationResultQualifier': {'ResourceId': 'AIDAIDFOUX2OSRO6DO7XL'}}},
            {'EvaluationResultIdentifier': {'EvaluationResultQualifier': {'ResourceId': 'AIDAIDFOUX2OSRO6DO7XM'}}}]}
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=old_eval)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'AIDAIDFOUX2OSRO6DO7XL'))
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', compliance_resource_type='AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected, 3)

class Scenario_1_TestInvalidRuleParameters(unittest.TestCase):

    def test_Scenario_1_invalid_rule_parameters_all_numbers(self):
        ruleParam = '{ "WhitelistedUserList" : "868391223"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_Scenario_1_invalid_rule_parameters_incorrect_separators(self):
        ruleParam = '{ "WhitelistedUserList" : "AIDAERTMGTRH566FGGC/AIDAICVB3PKAQMPEGDAQ3/AIDAICVB3PKAQMPEGDPID"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_Scenario_1_invalid_rule_parameters_special_characters(self):
        # if the parameter has invalid character
        ruleParam = '{ "WhitelistedUserList" : "IDAICVB3PKAQM!(GDW2C,AIDAICVB3PKA*MPEGDAQ3"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_Scenario_1_invalid_rule_parameters_does_not_begin_with_AIDA(self):
        ruleParam = '{ "WhitelistedUserList" : "IDAICVB3PKAQM,AIQAICVB3PKADMPEGDAQ3"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')


class Scenario_2_TestWhitelistedUser(unittest.TestCase):

    def test_Scenario_2_user_is_whitelisted(self):
        user_list = {'Users': [
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XN',
             'UserName': 'user-name-1'},
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XM',
             'UserName': 'user-name-2'}]}
        iam_client_mock.list_users = MagicMock(return_value=user_list)
        ruleParam = '{ "WhitelistedUserList" : "AIDAIDFOUX2OSRO6DO7XM, AIDAIDFOUX2OSRO6DO7XN"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN', annotation='The user (user-name-1) is whitelisted.'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM', annotation='The user (user-name-2) is whitelisted.'))
        assert_successful_evaluation(self, response, resp_expected, 2)


class Scenario_3_to_6_TestMFA(unittest.TestCase):

    user_list = {'Users': [
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XM',
             'UserName': 'user-name-1'},
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XN',
             'UserName': 'user-name-2'}]}

    def constructMFADeviceList(self,UserName):
        deviceList = { 'MFADevices': [{'UserName': 'CompliantUser', 'SerialNumber': 'ARN:IAM'}]}
        return deviceList

    def test_Scenario_3_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_mfa_devices = MagicMock(side_effect=self.constructMFADeviceList)
        ruleParam = '{ "WhitelistedUserList" : "AIDAICVB3PKAQMPEGDW2C"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_Scenario_4_Non_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_mfa_devices = MagicMock(return_value={"MFADevices":[]})
        ruleParam = '{ "WhitelistedUserList" : "AIDAICVB3PKAQMPEGDW2C"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event,{})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM', annotation='The user (user-name-1) has no MFA Device detected.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN', annotation='The user (user-name-2) has no MFA Device detected.'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_Scenario_5_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_mfa_devices = MagicMock(side_effect=self.constructMFADeviceList)
        lambda_event = build_lambda_scheduled_event()
        response = rule.lambda_handler(lambda_event,{})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_Scenario_6_Non_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.list_mfa_devices = MagicMock(return_value={"MFADevices":[]})
        lambda_event = build_lambda_scheduled_event()
        response = rule.lambda_handler(lambda_event,{})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM', annotation='The user (user-name-1) has no MFA Device detected.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN', annotation='The user (user-name-2) has no MFA Device detected.'))
        assert_successful_evaluation(self, response, resp_expected, 2)

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': True,
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
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
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