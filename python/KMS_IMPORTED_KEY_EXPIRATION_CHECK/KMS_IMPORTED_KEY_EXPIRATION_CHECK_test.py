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
from datetime import datetime, timedelta
from dateutil import tz

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

RULE = __import__('KMS_IMPORTED_KEY_EXPIRATION_CHECK')

class ComplianceTest(unittest.TestCase):
    def test_scenario_1_no_imported_keys_present(self):
        list_keys_no_imported = {'Keys' : [
            {'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'}
        ]}
        key_metadata = {}
        key_metadata['aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'] = {
            'KeyMetadata' : {
                'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab',
                'Origin' : 'AWS_KMS'
            }
        }
        KMS_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": KMS_CLIENT_MOCK,
            "paginate.return_value": [list_keys_no_imported],
            "describe_key.side_effect": lambda KeyId: key_metadata[KeyId]
            })
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"daysToExpiration" : "10"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE',
                                                     compliance_resource_type='AWS::::Account',
                                                     compliance_resource_id='123456789012'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_2_invalid_days_to_expiration(self):
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"daysToExpiration" : ""}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE',
                                                     compliance_resource_type='AWS::::Account',
                                                     compliance_resource_id='123456789012'))
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'daysToExpiration must be provided as a parameter.')

    def test_scenario_3_imported_key_does_not_expire(self):
        list_keys_no_imported = {'Keys': [
            {'KeyId': 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'}
        ]}
        key_metadata = {}
        key_metadata['aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'] = {
            'KeyMetadata' : {
                'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab',
                'Origin' : 'EXTERNAL',
                'ExpirationModel' : 'KEY_MATERIAL_DOES_NOT_EXPIRE'
            }
        }
        KMS_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": KMS_CLIENT_MOCK,
            "paginate.return_value": [list_keys_no_imported],
            "describe_key.side_effect": lambda KeyId: key_metadata[KeyId]
            })
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"daysToExpiration" : "10"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE',
                                                     compliance_resource_type='AWS::::Account',
                                                     compliance_resource_id='123456789012'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_4_key_expires_before_days_to_expiration(self):
        current_day = datetime.now(tz.tzlocal())
        day_to_expire = timedelta(days=9)
        list_keys_no_imported = {'Keys' : [
            {'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'}
        ]}
        key_metadata = {}
        key_metadata['aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'] = {
            'KeyMetadata' : {
                'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab',
                'Origin' : 'EXTERNAL',
                'ExpirationModel' : 'KEY_MATERIAL_EXPIRES',
                'ValidTo' : current_day + day_to_expire
            }
        }
        KMS_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": KMS_CLIENT_MOCK,
            "paginate.return_value": [list_keys_no_imported],
            "describe_key.side_effect": lambda KeyId: key_metadata[KeyId]
            })
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"daysToExpiration" : "10"}'), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT',
                                                     compliance_resource_type='AWS::KMS::Key',
                                                     compliance_resource_id='aaaaaaa-25bf-4d7b-abd7-ade10483c4ab',
                                                     annotation='The KMS key expires in less than 10 days.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_5_key_expires_after_days_to_expiration(self):
        current_day = datetime.now(tz.tzlocal())
        day_to_expire = timedelta(days=12)
        list_keys_no_imported = {'Keys' : [
            {'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'}
        ]}
        key_metadata = {}
        key_metadata['aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'] = {
            'KeyMetadata' : {
                'KeyId' : 'aaaaaaa-25bf-4d7b-abd7-ade10483c4ab',
                'Origin' : 'EXTERNAL',
                'ExpirationModel' : 'KEY_MATERIAL_EXPIRES',
                'ValidTo' : current_day + day_to_expire
            }
        }
        KMS_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": KMS_CLIENT_MOCK,
            "paginate.return_value": [list_keys_no_imported],
            "describe_key.side_effect": lambda KeyId: key_metadata[KeyId]
            })
        response = RULE.lambda_handler(build_lambda_scheduled_event('{"daysToExpiration" : "10"}'), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response('COMPLIANT',
                                    compliance_resource_type='AWS::KMS::Key',
                                    compliance_resource_id='aaaaaaa-25bf-4d7b-abd7-ade10483c4ab'))
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
