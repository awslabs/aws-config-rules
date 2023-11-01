import sys
import unittest
from botocore.exceptions import ClientError

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::Logs::LogGroup'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
LOGS_CLIENT_MOCK = MagicMock()


class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'logs':
            return LOGS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")


sys.modules['boto3'] = Boto3Mock()

RULE = __import__('CLOUDWATCH_LOG_GROUP_RETENTION_NEVER_EXPIRE_CHECK')


class ComplianceTest(unittest.TestCase):

    rule_valid_parameters_value = '{"retentionInDays":"60"}'
    rule_empty_parameter = '{}'

    zero_log_groups = {
        "logGroups": [
        ]
    }

    log_group_retention_set_to_never_expire = {
        "logGroups": [
            {
                "logGroupName": "/aws/lambda/ALBLambda",
            }
        ]
    }

    log_group_retention_set_in_days = {
        "logGroups": [
            {
                "logGroupName": "/aws/lambda/ALBLambda",
                "retentionInDays": "60",
            }
        ]
    }

    def setUp(self):
        pass
    # Scenario 1

    def test_no_loggroups_present(self):
        LOGS_CLIENT_MOCK.describe_log_groups = MagicMock(
            return_value=self.zero_log_groups)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(
            build_lambda_scheduled_event(self.rule_empty_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 2
    def test_log_group_retention_set_to_never_expire(self):
        LOGS_CLIENT_MOCK.describe_log_groups = MagicMock(
            return_value=self.log_group_retention_set_to_never_expire)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(
            build_lambda_scheduled_event(self.rule_empty_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '/aws/lambda/ALBLambda',
                             'AWS::Logs::LogGroup', 'This CloudWatch Log Group has a retention period set to Never Expire'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 3
    def test_log_group_retention_set_in_days(self):
        LOGS_CLIENT_MOCK.describe_log_groups = MagicMock(
            return_value=self.log_group_retention_set_in_days)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(
            build_lambda_scheduled_event(self.rule_empty_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '/aws/lambda/ALBLambda',
                             'AWS::Logs::LogGroup', 'This CloudWatch Log Group has a retention period set to 60 days'))
        assert_successful_evaluation(self, response, resp_expected)


####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName': 'myrule',
        'executionRoleArn': 'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken': 'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return


def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName': 'myrule',
        'executionRoleArn': 'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken': 'token'
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
        test_class.assertEqual(
            resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEqual(
            resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEqual(
            resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEqual(
                resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEqual(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEqual(
                response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEqual(
                response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEqual(
                response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEqual(
                    response_expected['Annotation'], response[i]['Annotation'])


def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code,
                               response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message,
                               response['customerErrorMessage'])
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
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
