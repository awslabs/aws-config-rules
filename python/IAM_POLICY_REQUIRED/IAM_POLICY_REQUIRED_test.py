import json
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
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::Role'

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


def build_user_configuration_item(attached_policies_arns, user_groups, user_name="test-user"):
    return {
        "configurationItemDiff": None,
        "configurationItem": {
            "relatedEvents": [],
            "relationships": [
                {
                    "resourceId": "ABCDEFGHI12JKL4MNO5PQ",
                    "resourceName": arn.rsplit("/")[-1],
                    "resourceType": "AWS::IAM::Policy",
                    "name": "Is attached to CustomerManagedPolicy"
                } for arn in attached_policies_arns
            ],
            "configuration": {
                "groupList": list(user_groups.keys()),
                "userName": user_name,
                "userId": "ABCDEFGHI12JKL4MNO5PQ",
                "arn": "arn:aws:iam::0123456789012:user{Name}".format(Name=user_name),
                "createDate": "2018-08-30T13:25:10.000Z",
                "assumeRolePolicyDocument": "{}",
                "instanceProfileList": [],
                "rolePolicyList": [],
                "attachedManagedPolicies": [
                    {
                        "policyName": arn.rsplit("/")[-1],
                        "policyArn": arn
                    } for arn in attached_policies_arns
                ],
                "permissionsBoundary": None
            },
            "supplementaryConfiguration": {},
            "tags": {},
            "configurationItemVersion": "1.3",
            "configurationItemCaptureTime": "2018-09-07T11:24:32.476Z",
            "configurationStateId": 12345678901,
            "awsAccountId": "0123456789012",
            "configurationItemStatus": "OK",
            "resourceType": "AWS::IAM::User",
            "resourceId": "ABCDEFGHI12JKL4MNO5PQ",
            "resourceName": user_name,
            "ARN": "arn:aws:iam::0123456789012:user/{}".format(user_name),
            "awsRegion": "global",
            "availabilityZone": "Not Applicable",
            "configurationStateMd5Hash": "",
            "resourceCreationTime": "2018-08-30T13:25:10.000Z"
        },
        "notificationCreationTime": "2018-09-21T09:24:28.962Z",
        "messageType": "ConfigurationItemChangeNotification",
        "recordVersion": "1.3"
    }


def build_role_configuration_item(attached_policies_arns, role_name="test-role", path="/"):
    return {
        "configurationItemDiff": None,
        "configurationItem": {
            "relatedEvents": [],
            "relationships": [
                {
                    "resourceId": "ABCDEFGHI12JKL4MNO5PQ",
                    "resourceName": arn.rsplit("/")[-1],
                    "resourceType": "AWS::IAM::Policy",
                    "name": "Is attached to CustomerManagedPolicy"
                } for arn in attached_policies_arns
            ],
            "configuration": {
                "path": path,
                "roleName": role_name,
                "roleId": "ABCDEFGHI12JKL4MNO5PQ",
                "arn": "arn:aws:iam::0123456789012:role{Path}{Name}".format(Path=path, Name=role_name),
                "createDate": "2018-08-30T13:25:10.000Z",
                "assumeRolePolicyDocument": "{}",
                "instanceProfileList": [],
                "rolePolicyList": [],
                "attachedManagedPolicies": [
                    {
                        "policyName": arn.rsplit("/")[-1],
                        "policyArn": arn
                    } for arn in attached_policies_arns
                ],
                "permissionsBoundary": None
            },
            "supplementaryConfiguration": {},
            "tags": {},
            "configurationItemVersion": "1.3",
            "configurationItemCaptureTime": "2018-09-07T11:24:32.476Z",
            "configurationStateId": 12345678901,
            "awsAccountId": "0123456789012",
            "configurationItemStatus": "OK",
            "resourceType": "AWS::IAM::Role",
            "resourceId": "ABCDEFGHI12JKL4MNO5PQ",
            "resourceName": role_name,
            "ARN": "arn:aws:iam::0123456789012:role/{}".format(role_name),
            "awsRegion": "global",
            "availabilityZone": "Not Applicable",
            "configurationStateMd5Hash": "",
            "resourceCreationTime": "2018-08-30T13:25:10.000Z"
        },
        "notificationCreationTime": "2018-09-21T09:24:28.962Z",
        "messageType": "ConfigurationItemChangeNotification",
        "recordVersion": "1.3"
    }


rule = __import__('IAM_POLICY_REQUIRED')

class TestPolicyRequired(unittest.TestCase):

    rule_parameters = '{"policyArns":"arn:aws:iam::aws:policy/AdministratorAccess", "exceptionList": ""}'
    invoking_event_iam_role_sample = json.dumps(build_role_configuration_item(['arn:aws:iam::aws:policy/AdministratorAccess']))
    invoking_event_iam_user_sample = json.dumps(build_user_configuration_item([
        'arn:aws:iam::aws:policy/AdministratorAccess'], {'group1': [{'PolicyArn':'arn:aws:iam::aws:policy/AdministratorAccess'}]}))

    def test_it_marks_service_roles_as_compliant(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(
            self.invoking_event_iam_role_sample.replace("role/", "role/aws-service-role/"), self.rule_parameters), {})
        resp_expected = [build_expected_response('COMPLIANT', ANY, 'AWS::IAM::Role', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_ignored_roles_as_compliant(self):
        rule_parameters = '{"policyArns":"arn:aws:iam::aws:policy/AdministratorAccess", "exceptionList": "users:[test-user],roles:[test-role]"}'
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(
            self.invoking_event_iam_role_sample, rule_parameters), {})
        resp_expected = [build_expected_response('COMPLIANT', ANY, 'AWS::IAM::Role', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_ignored_users_as_compliant(self):
        rule_parameters = '{"policyArns":"arn:aws:iam::aws:policy/AdministratorAccess", "exceptionList": "users:[test-user]"}'
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_configurationchange_event(
            self.invoking_event_iam_user_sample, rule_parameters), {})
        resp_expected = [build_expected_response('COMPLIANT', ANY, 'AWS::IAM::User', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_roles_with_policy_as_compliant(self):
        invoking_event = json.dumps(build_role_configuration_item(['arn:aws:iam::aws:policy/AdministratorAccess']))
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = [build_expected_response('COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::Role', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_users_with_policy_as_compliant(self):
        invoking_event = json.dumps(build_user_configuration_item([
            'arn:aws:iam::aws:policy/AdministratorAccess'], {}))
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})

        resp_expected = [build_expected_response('COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::User', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_users_in_group_with_policy_as_compliant(self):
        invoking_event = json.dumps(build_user_configuration_item(
            [], {'group1': ['arn:aws:iam::aws:policy/AdministratorAccess']}))
        rule.ASSUME_ROLE_MODE = False
        iam_client_mock.configure_mock(**{
            "get_paginator.return_value": iam_client_mock,
            "paginate.return_value": iam_client_mock,
            "result_key_iters.return_value": [
                [{
                    'PolicyName': 'AdministratorAccess',
                    'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess',
                }]
            ]
        })
        iam_client_mock.list_attached_group_policies.__name__ = 'list_attached_group_policies'
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})

        resp_expected = [build_expected_response('COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::User', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_users_without_policy_as_non_compliant(self):
        invoking_event = json.dumps(build_user_configuration_item([], {}))
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})

        resp_expected = [build_expected_response('NON_COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::User', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_marks_roles_without_policy_as_non_compliant(self):
        invoking_event = json.dumps(build_role_configuration_item([]))
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})

        resp_expected = [build_expected_response('NON_COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::Role', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_handles_customer_managed_policy_arns(self):
        invoking_event = json.dumps(build_role_configuration_item(
            ['arn:aws:iam::012345678912:policy/my-policy']))
        rule_parameters = '{"policyArns":"arn:aws:iam::012345678912:policy/my-policy", "exceptionList": ""}'
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters), {})

        resp_expected = [build_expected_response('COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::Role', ANY)]
        assert_successful_evaluation(self, response, resp_expected)

    def test_it_handles_customer_managed_policy_arns_with_paths(self):
        invoking_event = json.dumps(build_role_configuration_item(
            ['arn:aws:iam::012345678912:policy/my-path/my-policy']))
        rule_parameters = '{"policyArns":"arn:aws:iam::012345678912:policy/my-path/my-policy", "exceptionList": ""}'
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters), {})

        resp_expected = [build_expected_response('COMPLIANT', 'ABCDEFGHI12JKL4MNO5PQ', 'AWS::IAM::Role', ANY)]
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
        invoking_event = json.dumps(build_role_configuration_item(
            ['arn:aws:iam::012345678912:policy/my-policy']))
        rule_parameters = '{"policyArns":"arn:aws:iam::012345678912:policy/my-policy", "exceptionList": ""}'
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        invoking_event = json.dumps(build_role_configuration_item(
            ['arn:aws:iam::012345678912:policy/my-policy']))
        rule_parameters = '{"policyArns":"arn:aws:iam::012345678912:policy/my-policy", "exceptionList": ""}'
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
