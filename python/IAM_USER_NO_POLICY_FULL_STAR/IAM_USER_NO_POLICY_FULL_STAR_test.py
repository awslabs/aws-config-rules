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
        elif client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_USER_NO_POLICY_FULL_STAR')

class ComplianceTest(unittest.TestCase):

    invoking_event = '{"configurationItemDiff":"SomeDifference", "notificationCreationTime":"SomeTime", "messageType":"ConfigurationItemChangeNotification", "recordVersion":"SomeVersion", "configurationItem":{ "resourceType":"AWS::IAM::User","configurationItemStatus":"ResourceDiscovered", "resourceId":"AIDAICVB3PKAQMPEGDW2C", "configurationItemCaptureTime":"2018-02-20T06:56:55.533Z", "configuration":{"userName": "someusername"}}}'

    list_user_policy_names = {'PolicyNames': ['policyname1', 'policyname2']}
    get_user_policy_doc = {'PolicyDocument': {"Statement": [{"Effect": "Allow", "Action": "*"}]}}
    no_list_user_policy_names = {'PolicyNames': []}
    list_attached_policy_arn = {'AttachedPolicies': [{'PolicyArn': 'arn1', 'PolicyName': 'policyname1'},{'PolicyArn': 'arn2', 'PolicyName': 'policyname1'}]}
    get_policy = {'Policy': {'DefaultVersionId': 'v2'}}
    get_managed_policy_doc_allow = {"PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "*"}]}}}
    get_managed_policy_doc_deny = {"PolicyVersion": {"Document": {"Statement": [{"Effect": "Deny", "Action": "*"}]}}}

    def test_non_compliant_inline(self):
        iam_client_mock.list_user_policies = MagicMock(return_value=self.list_user_policy_names)
        iam_client_mock.get_user_policy = MagicMock(return_value=self.get_user_policy_doc)
        lambdaEvent = build_lambda_configurationchange_event(invoking_event=self.invoking_event)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation='The inline policy "policyname1" attached to the user "someusername" has full star allow permissions.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_non_compliant_managed(self):
        iam_client_mock.list_user_policies = MagicMock(return_value=self.no_list_user_policy_names)
        iam_client_mock.list_attached_user_policies = MagicMock(return_value=self.list_attached_policy_arn)
        iam_client_mock.get_policy = MagicMock(return_value=self.get_policy)
        iam_client_mock.get_policy_version = MagicMock(return_value=self.get_managed_policy_doc_allow)
        lambdaEvent = build_lambda_configurationchange_event(invoking_event=self.invoking_event)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation='The managed policy "policyname1" attached to the user "someusername" has full star allow permissions.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliant_managed(self):
        iam_client_mock.list_user_policies = MagicMock(return_value=self.no_list_user_policy_names)
        iam_client_mock.list_attached_user_policies = MagicMock(return_value=self.list_attached_policy_arn)
        iam_client_mock.get_policy = MagicMock(return_value=self.get_policy)
        iam_client_mock.get_policy_version = MagicMock(return_value=self.get_managed_policy_doc_deny)
        lambdaEvent = build_lambda_configurationchange_event(invoking_event=self.invoking_event)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C'))
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
