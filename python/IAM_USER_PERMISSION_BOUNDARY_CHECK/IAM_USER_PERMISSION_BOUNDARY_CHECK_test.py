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
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
IAM_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'sts':
            return STS_CLIENT_MOCK
        elif client_name == 'iam':
            return IAM_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('IAM_USER_PERMISSION_BOUNDARY_CHECK')

class TESTInvalidpermissionboundary(unittest.TestCase):
    user_list = {'Users': [{'UserId': 'AIDAIDFOUX2OSRO6DO7XM', 'UserName': 'user-name-1'}, {'UserId': 'AIDAIDFOUX2OSRO6DO7XN', 'UserName': 'user-name-2'}]}

    # Premission Boundary Name is provided as the input but policy name is in invalid format.

    def test_scenario1(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.get_user = MagicMock(return_value={'User':{}})
        rule_param = "{\"policyArns\":\"arn:aws:iam::aws:/AdministratorAccess\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', customer_error_message='The parameter should be a valid ARN format of the policy')

class TESTScenarios2to8(unittest.TestCase):
    user_list = {'Users': [{'UserId': 'AIDAIDFOUX2OSRO6DO7XM', 'UserName': 'user-name-1'}, {'UserId': 'AIDAIDFOUX2OSRO6DO7XN', 'UserName': 'user-name-2'}]}

    def construct_permission_list(self, UserName):
        user_info_list = {"User": {"UserName": "user-name-1", "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, "UserId": "AIDAJDTYJDDPUWJ7IR3G2", "Arn": "arn:aws:iam::677885075477:user/ddbtest"}}
        return user_info_list

    # No IAM users present in the account.
    def test_scenario2(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value={"Users":[]})
        lambda_event = build_lambda_scheduled_event()
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    # Atleast 1 IAM user present in the account but No Permission policies in the account
    def test_scenario3(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.list_policies = MagicMock(return_value={"Policies": []})
        lambda_event = build_lambda_scheduled_event()
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    # Permission Boundary is present in the Account but IAM user does not have it attached.
    def test_scenario4(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.get_user = MagicMock(return_value={'User':{}})
        lambda_event = build_lambda_scheduled_event()
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    # Permission Boundary is present in the Account and IAM user does have it attached.
    def test_scenario5(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.get_user = MagicMock(side_effect=self.construct_permission_list)
        lambda_event = build_lambda_scheduled_event()
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    # Permission Boundary Name is provided as the input and IAM user does have it attached.
    def test_scenario6(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.get_user = MagicMock(side_effect=self.construct_permission_list)
        rule_param = "{\"policyArns\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    # Permission Boundary Name is provided as the input and IAM user does not have any permission boundary attached.
    def test_scenario7(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.get_user = MagicMock(return_value={'User':{}})
        IAM_CLIENT_MOCK.get_user = MagicMock(return_value={'User':{}})
        rule_param = "{\"policyArns\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    # Permission Boundary Name is provided as the input but IAM user does not have it attached.
    def test_scenario8(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.get_user = MagicMock(return_value={"User": {"UserName": "user-name-2", "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/AdminAccess"}, "UserId": "AIDAIDFOUX2OSRO6DO7XN", "Arn": "arn:aws:iam::677885075477:user/ddbtest"}})
        IAM_CLIENT_MOCK.get_user = MagicMock(return_value={"User": {"UserName": "user-name-1", "PermissionsBoundary": {"PermissionsBoundaryType": "Policy", "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/AAccess"}, "UserId": "AIDAIDFOUX2OSRO6DO7XN", "Arn": "arn:aws:iam::677885075477:user/ddbtest"}})
        rule_param = "{\"policyArns\":\"arn:aws:iam::aws:policy/AdministratorAccess\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
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
