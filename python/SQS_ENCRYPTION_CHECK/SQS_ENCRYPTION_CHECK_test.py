# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
DEFAULT_RESOURCE_TYPE = 'AWS::SQS::Queue'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
SQS_MOCK = MagicMock()
KMS_MOCK = MagicMock()


class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'sqs':
            return SQS_MOCK
        if client_name == 'kms':
            return KMS_MOCK
        raise Exception("Attempting to create an unknown client")


sys.modules['boto3'] = Boto3Mock()

RULE = __import__('SQS_ENCRYPTION_CHECK')


def queue_attributes_side_effect(QueueUrl, AttributeNames):
    if QueueUrl in ["url/compliant-queue-01", "url/compliant-queue-02", "url/compliant-queue-03"]:
        return {"Attributes": {"KmsMasterKeyId": "alias/active-key"}}

    elif QueueUrl == "url/unencrypted-queue-01":
        return {"Attributes": {}}

    elif QueueUrl == "url/key-not-exist-01":
        return {"Attributes": {"KmsMasterKeyId": "alias/key-not-exist"}}
    elif QueueUrl == "url/key-not-enabled-01":
        return {"Attributes": {"KmsMasterKeyId": "alias/key-pending-deletion"}}


def describe_key_side_effect(KeyId):
    if KeyId == 'alias/active-key':
        return {"KeyMetadata": {"KeyManager": "AWS", "KeyState": "Enabled"}}
    if KeyId == 'alias/key-pending-deletion':
        return {"KeyMetadata": {"KeyManager": "AWS", "KeyState": "PendingDeletion"}}
    else:
        raise Exception('key not exist')


class TestHelperMixin:
    def _run_test(self, paginator_mock_data, rule_parameters, expected_response):
        paginator_mock = MagicMock()
        paginator_mock.paginate = MagicMock(side_effect=paginator_mock_data)

        SQS_MOCK.get_paginator = MagicMock(return_value=paginator_mock)

        SQS_MOCK.get_queue_attributes.side_effect = queue_attributes_side_effect

        KMS_MOCK.describe_key.side_effect = describe_key_side_effect

        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters=rule_parameters), {})

        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))


class ComplianceTest(unittest.TestCase, TestHelperMixin):
    rule_parameters = '{"ExemptedQueueNames": ".*(dev).*, .*(demo).*, exempted-queue-1, exempted-queue-2"}'

    def setUp(self):
        pass

    # Scenario: 1   - valid rule parameter
    def test_scenario_1_valid_rule_parameter(self):
        rule_parameters = {"ExemptedQueueNames": ".*(dev).*, name, xyz, sam.*"}
        results = RULE.evaluate_parameters(rule_parameters)
        self.assertEqual([".*(dev).*", "sam.*"], results["exempted_regex"])
        self.assertEqual(["name", "xyz"], results["exempted_names"])

    # Scenario: 2   - invalid rule parameter (empty)
    def test_scenario_2_empty_rule_parameter(self):
        rule_parameters = {}
        results = RULE.evaluate_parameters(rule_parameters)
        self.assertEqual([], results["exempted_regex"])
        self.assertEqual([], results["exempted_names"])

    # Scenario: 2   - invalid rule parameter (wrong type)
    def test_scenario_2_invalid_rule_parameter_type(self):
        rule_parameters = {"ExemptedQueueNames": 100}
        results = RULE.evaluate_parameters(rule_parameters)
        self.assertEqual([], results["exempted_regex"])
        self.assertEqual([], results["exempted_names"])

    # Scenario: 3   - exempted by name
    def test_scenario_3_exempted_by_name(self):
        paginator_mock_data = [
            [
                {'QueueUrls': ['url/exempted-queue-1', 'url/exempted-queue-2']}
            ]
        ]

        expected_response = [
            build_expected_response('NOT_APPLICABLE', 'url/exempted-queue-1', DEFAULT_RESOURCE_TYPE,
                                    RULE.EXEMPTED_BY_NAME.format("exempted-queue-1")),
            build_expected_response('NOT_APPLICABLE', 'url/exempted-queue-2', DEFAULT_RESOURCE_TYPE,
                                    RULE.EXEMPTED_BY_NAME.format("exempted-queue-2"))
        ]

        self._run_test(paginator_mock_data, self.rule_parameters, expected_response)

    # Scenario: 4   - exempted by regex
    def test_scenario_4_exempted_by_regex(self):
        paginator_mock_data = [
            [
                {'QueueUrls': ['url/dev-queue', 'url/my-demo-queue']}
            ]
        ]

        expected_response = [
            build_expected_response('NOT_APPLICABLE', 'url/dev-queue', DEFAULT_RESOURCE_TYPE,
                                    RULE.EXEMPTED_BY_REGEX.format(".*(dev).*")),
            build_expected_response('NOT_APPLICABLE', 'url/my-demo-queue', DEFAULT_RESOURCE_TYPE,
                                    RULE.EXEMPTED_BY_REGEX.format(".*(demo).*"))
        ]

        self._run_test(paginator_mock_data, self.rule_parameters, expected_response)

    # Scenario: 5   - non compliant queue; no key is set
    def test_scenario_5_encryption_disabled(self):
        paginator_mock_data = [
            [
                {'QueueUrls': ['url/unencrypted-queue-01']}
            ]
        ]

        expected_response = [
            build_expected_response('NON_COMPLIANT', 'url/unencrypted-queue-01', DEFAULT_RESOURCE_TYPE,
                                    RULE.ENCRYPTION_DISABLED)
        ]

        self._run_test(paginator_mock_data, self.rule_parameters, expected_response)

    # Scenario: 6   - non compliant queue; key doesn't exist
    def test_scenario_6_key_not_exist(self):
        paginator_mock_data = [
            [
                {'QueueUrls': ['url/key-not-exist-01']}
            ]
        ]

        expected_response = [
            build_expected_response('NON_COMPLIANT', 'url/key-not-exist-01', DEFAULT_RESOURCE_TYPE,
                                    RULE.KEY_DOES_NOT_EXIST.format("alias/key-not-exist"))
        ]

        self._run_test(paginator_mock_data, self.rule_parameters, expected_response)

    # Scenario: 7   - non compliant queue; key isn't enabled
    def test_scenario_7_key_not_enabled(self):
        paginator_mock_data = [
            [
                {'QueueUrls': ['url/key-not-enabled-01']}
            ]
        ]

        expected_response = [
            build_expected_response('NON_COMPLIANT', 'url/key-not-enabled-01', DEFAULT_RESOURCE_TYPE,
                                    RULE.KEY_IS_NOT_ENABLED.format(
                                        "alias/key-pending-deletion", "PendingDeletion"))
        ]

        self._run_test(paginator_mock_data, self.rule_parameters, expected_response)

    # Scenario: 8   - compliant queue
    def test_scenario_8_compliant_queues(self):
        paginator_mock_data = [
            [
                {'QueueUrls': ['url/compliant-queue-01', 'url/compliant-queue-02']},
                {'QueueUrls': ['url/compliant-queue-03']}
            ]
        ]

        expected_response = [
            build_expected_response('COMPLIANT', 'url/compliant-queue-01', DEFAULT_RESOURCE_TYPE, RULE.COMPLIANT),
            build_expected_response('COMPLIANT', 'url/compliant-queue-02', DEFAULT_RESOURCE_TYPE, RULE.COMPLIANT),
            build_expected_response('COMPLIANT', 'url/compliant-queue-03', DEFAULT_RESOURCE_TYPE, RULE.COMPLIANT)
        ]

        self._run_test(paginator_mock_data, self.rule_parameters, expected_response)


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


def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE,
                            annotation=None):
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
