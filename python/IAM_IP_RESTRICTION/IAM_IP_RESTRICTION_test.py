# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore

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
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'iam':
            return IAM_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('IAM_IP_RESTRICTION')

class InvalidParameterTest(unittest.TestCase):
    def setUp(self):
        CONFIG_CLIENT_MOCK.reset_mock()
        IAM_CLIENT_MOCK.reset_mock()

    too_many_char = ''.join([str(c) for c in range(60)])
    invalid_params = {
        'tooManyChar': '{"WhitelistedUserNames":"test-user-' + too_many_char + '"}',
        'invalidMaxIpNums': '{"WhitelistedUserNames":"test-user01,test-user02", "maxIpNums":"0"}',
    }

    def test_scenario02_user_whitelist_too_many_characters(self):
        response = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.invalid_params['tooManyChar']), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_scenario03_max_ip_num_less_than_1(self):
        response = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.invalid_params['invalidMaxIpNums']), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        CONFIG_CLIENT_MOCK.reset_mock()
        IAM_CLIENT_MOCK.reset_mock()

    user_list_empty = {"Users" : []}
    user_whitelist = {'UserId': 'AIDAJYPPIFB65RV8YYLDU', 'UserName': 'sampleUser1'}
    user_not_whitelist = {'UserId': 'AIDAJYPPIFB65RV8YYLDV', 'UserName': 'sampleUser2'}
    user_list = {"Users": [user_whitelist, user_not_whitelist]}
    user_policy_name = 'IAMIPRestrictPolicy'
    allow_ip = '192.169.30.1/32'

    def test_scenario01_no_iam_users(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list_empty)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response("NOT_APPLICABLE", "123456789012", compliance_resource_type="AWS::::Account"))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario04_compliant_user_whitelist(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario05_noncompliant_user_inline_policy_not_ip_allowed(self):
        self.__mock_only_user_inline_policy_not_ip_allowed()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("NON_COMPLIANT", self.user_not_whitelist['UserId'], annotation=f"This user {self.user_not_whitelist['UserName']} is not IP restricted."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario06_noncompliant_user_attached_policy_not_ip_allowed(self):
        self.__mock_only_user_attached_policy_not_ip_allowed()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("NON_COMPLIANT", self.user_not_whitelist['UserId'], annotation=f"This user {self.user_not_whitelist['UserName']} is not IP restricted."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario07_noncompliant_group_inline_policy_not_ip_allowed(self):
        self.__mock_only_group_inline_policy_not_ip_allowed()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("NON_COMPLIANT", self.user_not_whitelist['UserId'], annotation=f"This user {self.user_not_whitelist['UserName']} is not IP restricted."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario08_noncompliant_group_attached_policy_not_ip_allowed(self):
        self.__mock_only_group_attached_policy_not_ip_allowed()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("NON_COMPLIANT", self.user_not_whitelist['UserId'], annotation=f"This user {self.user_not_whitelist['UserName']} is not IP restricted."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario09_compliant_all_policy_ip_allowed(self):
        self.__mock_all_policy_ip_allowed()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("COMPLIANT", self.user_not_whitelist['UserId']))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario10_compliant_user_inline_policy_ip_denied(self):
        self.__mock_user_inline_policy_ip_denied()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("COMPLIANT", self.user_not_whitelist['UserId']))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario11_compliant_user_attached_policy_ip_denied(self):
        self.__mock_user_attached_policy_ip_denied()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("COMPLIANT", self.user_not_whitelist['UserId']))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario12_compliant_group_inline_policy_ip_denied(self):
        self.__mock_group_inline_policy_ip_denied()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("COMPLIANT", self.user_not_whitelist['UserId']))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario13_compliant_group_attached_policy_ip_denied(self):
        self.__mock_group_attached_policy_ip_denied()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("COMPLIANT", self.user_not_whitelist['UserId']))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario14_noncompliant_allowed_ip_addresses_greater_than_max_ip_nums(self):
        self.__mock_ip_restricted_greather_than_max_ip_nums()
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"WhitelistedUserNames":"sampleUser1"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response("COMPLIANT", self.user_whitelist['UserId'], annotation=f"This user {self.user_whitelist['UserName']} is whitelisted."))
        resp_expected.append(build_expected_response("NON_COMPLIANT", self.user_not_whitelist['UserId'], annotation=f"IAM Policy includes more than maximum ip addresses: {RULE.DEFAULT_MAX_IP_NUMS+1}"))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def __mock_only_user_inline_policy_not_ip_allowed(self):
        self.__mock_base()
        ip_allowed_policy = self.__ip_restricted_policy('Allow')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': ip_allowed_policy['PolicyDocument']}})

    def __mock_only_user_attached_policy_not_ip_allowed(self):
        self.__mock_base()
        ip_allowed_policy = self.__ip_restricted_policy('Allow')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': base_policy['PolicyDocument']}})

    def __mock_only_group_inline_policy_not_ip_allowed(self):
        self.__mock_base()
        ip_allowed_policy = self.__ip_restricted_policy('Allow')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': ip_allowed_policy['PolicyDocument']}})

    def __mock_only_group_attached_policy_not_ip_allowed(self):
        self.__mock_base()
        ip_allowed_policy = self.__ip_restricted_policy('Allow')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': base_policy['PolicyDocument']}})

    def __mock_all_policy_ip_allowed(self):
        self.__mock_base()
        ip_allowed_policy = self.__ip_restricted_policy('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=ip_allowed_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': ip_allowed_policy['PolicyDocument']}})

    def __mock_user_inline_policy_ip_denied(self):
        self.__mock_base()
        ip_denied_policy = self.__ip_restricted_policy('Deny')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=ip_denied_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': base_policy['PolicyDocument']}})

    def __mock_user_attached_policy_ip_denied(self):
        self.__mock_base()
        ip_denied_policy = self.__ip_restricted_policy('Deny')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': ip_denied_policy['PolicyDocument']}})

    def __mock_group_inline_policy_ip_denied(self):
        self.__mock_base()
        ip_denied_policy = self.__ip_restricted_policy('Deny')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=ip_denied_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': base_policy['PolicyDocument']}})

    def __mock_group_attached_policy_ip_denied(self):
        self.__mock_base()
        ip_denied_policy = self.__ip_restricted_policy('Deny')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': ip_denied_policy['PolicyDocument']}})

    def __mock_ip_restricted_greather_than_max_ip_nums(self):
        self.__mock_base()
        ip_denied_policy = self.__ip_restricted_greather_than_max_ip_nums_policy('Deny')
        base_policy = self.__policy_base('Allow')
        IAM_CLIENT_MOCK.get_user_policy = MagicMock(return_value=ip_denied_policy)
        IAM_CLIENT_MOCK.get_group_policy = MagicMock(return_value=base_policy)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value={'PolicyVersion': {'Document': base_policy['PolicyDocument']}})

    def __mock_base(self):
        inline_policy_name = {'PolicyNames': [self.user_policy_name]}
        attached_policy_name = {'AttachedPolicies': [{'PolicyName': 'samplePolicy', 'PolicyArn': 'arn:aws:iam::123456789000:policy/samplePolicy'}]}
        group_for_user = {'Groups': [{'GroupName': 'sampleGroup'}]}
        policy_version = {'Policy': {'DefaultVersionId': 'v1'}}

        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        IAM_CLIENT_MOCK.list_user_policies = MagicMock(return_value=inline_policy_name)
        IAM_CLIENT_MOCK.list_attached_user_policies = MagicMock(return_value=attached_policy_name)
        IAM_CLIENT_MOCK.list_groups_for_user = MagicMock(return_value=group_for_user)
        IAM_CLIENT_MOCK.list_group_policies = MagicMock(return_value=inline_policy_name)
        IAM_CLIENT_MOCK.list_attached_group_policies(GroupName=attached_policy_name)
        IAM_CLIENT_MOCK.get_policy(PolicyArn=policy_version)

    def __ip_not_restricted_policy(self, effect):
        return self.__policy_base(effect)

    def __ip_restricted_policy(self, effect):
        if effect == 'Deny':
            condition = 'NotIpAddress'
        else:
            condition = 'IpAddress'

        policy = self.__policy_base(effect)
        policy['PolicyDocument']['Statement'][0]['Condition'] = {
            condition: {
                'aws:SourceIp': [self.allow_ip]
            }
        }
        return policy

    def __ip_restricted_greather_than_max_ip_nums_policy(self, effect):
        if effect == 'Deny':
            condition = 'NotIpAddress'
        else:
            condition = 'IpAddress'
        too_many_ip_addresses = [f'192.169.30.{n}/32' for n in range(RULE.DEFAULT_MAX_IP_NUMS+1)]

        policy = self.__policy_base(effect)
        policy['PolicyDocument']['Statement'][0]['Condition'] = {
            condition: {
                'aws:SourceIp': too_many_ip_addresses
            }
        }
        return policy

    def __policy_base(self, effect):
        policy = {
            'UserName': self.user_not_whitelist['UserName'],
            'PolicyName': self.user_policy_name,
            'PolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': '*',
                        'Resource': '*',
                        'Effect': effect
                    }
                ]
            }
        }
        return policy


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
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
