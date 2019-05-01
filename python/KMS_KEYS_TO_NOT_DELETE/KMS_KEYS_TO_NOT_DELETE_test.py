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

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::KMS::Key'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
KMS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'kms':
            return KMS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('KMS_KEYS_TO_NOT_DELETE')

class ComplianceTest(unittest.TestCase):

    kms_key_list = {"Keys": [{"KeyId": "83de41d6-6530-49c1-9cb7-1de1560ce5tg"}]}

    def setUp(self):
        pass

    def test_scenario_1_invalid_param(self):
        rule_param = "{\"kmsKeyIds\":\"83de41d66530-49c1-9cb7-1de1560ce5tg\"}"
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value=self.kms_key_list)
        KMS_CLIENT_MOCK.describe_key = MagicMock(return_value={"KeyMetadata":{}})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', customer_error_message='The KMS Key id should be in the right format.')

    def test_scenario_2_no_keys(self):
        rule_param = {}
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value={"Keys":[]})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_3_no_param(self):
        rule_param = {}
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value=self.kms_key_list)
        KMS_CLIENT_MOCK.describe_key = MagicMock(return_value={"KeyMetadata": {"KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER"}})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '83de41d6-6530-49c1-9cb7-1de1560ce5tg'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_4_noncomplaint(self):
        rule_param = {}
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value=self.kms_key_list)
        KMS_CLIENT_MOCK.describe_key = MagicMock(return_value={"KeyMetadata": {"KeyState": "PendingDeletion", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER"}})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '83de41d6-6530-49c1-9cb7-1de1560ce5tg', annotation='The KMS Key is scheduled for deletion.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_5_param_not(self):
        rule_param = "{\"kmsKeyIds\":\"fe727d4a-1bb7-4226-82d8-9d50b9aece5t\"}"
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value=self.kms_key_list)
        KMS_CLIENT_MOCK.describe_key = MagicMock(return_value={"KeyMetadata": {"KeyState": "PendingDeletion", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER"}})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'fe727d4a-1bb7-4226-82d8-9d50b9aece5t', annotation='The given kmsKeyId does not exist. Please verify the kmsKeyId and try again.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_6_complaint(self):
        rule_param = "{\"kmsKeyIds\":\"83de41d6-6530-49c1-9cb7-1de1560ce5tg\"}"
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value=self.kms_key_list)
        KMS_CLIENT_MOCK.describe_key = MagicMock(return_value={"KeyMetadata": {"KeyState": "Enabled", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER"}})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '83de41d6-6530-49c1-9cb7-1de1560ce5tg'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_7_noncomplaint(self):
        rule_param = "{\"kmsKeyIds\":\"83de41d6-6530-49c1-9cb7-1de1560ce5tg\"}"
        KMS_CLIENT_MOCK.list_keys = MagicMock(return_value=self.kms_key_list)
        KMS_CLIENT_MOCK.describe_key = MagicMock(return_value={"KeyMetadata": {"KeyState": "PendingDeletion", "Origin": "AWS_KMS", "KeyManager": "CUSTOMER"}})
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '83de41d6-6530-49c1-9cb7-1de1560ce5tg', annotation='The KMS Key is scheduled for deletion.'))
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
