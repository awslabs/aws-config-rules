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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
SAGEMAKER_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'sagemaker':
            return SAGEMAKER_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('SAGEMAKER_ENDPOINT_CONFIG_KMS_KEY_CONFIGURED')

class ComplianceTest(unittest.TestCase):

    rule_parameters_scenario3 = '{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487h3d, arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4edg-8131-7c98e9487e3d"}'
    list_endpoints_scenario3 = [{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    described_endpoints_scenario3 = [{'EndpointConfigName':'endpoint1', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'}, {'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2'}]

    rule_parameters_scenario4 = '{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487h3d, arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4edg-8131-7c98e9487e3d"}'
    list_endpoints_scenario4 = [{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    described_endpoints_scenario4 = [{'EndpointConfigName':'endpoint1', 'KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'}, {'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2', 'KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d'}]

    rule_parameters_scenario5 = '{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d, arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3f"}'
    list_endpoints_scenario5 = [{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    described_endpoints_scenario5 = [{'EndpointConfigName':'endpoint1', 'KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'}, {'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2', 'KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3f'}]

    rule_parameters_scenario6 = '{}'
    list_endpoints_scenario6 = [{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    described_endpoints_scenario6 = [{'EndpointConfigName':'endpoint1', 'KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'}, {'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2', 'KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3f'}]


    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    #Scenario 2 No Amazon SageMaker endpoint configs exist
    def test_scenario_2_no_endpoints(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": [{'EndpointConfigs': []}]})
        lambda_event = build_lambda_scheduled_event(rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3 Given: At least one Amazon SageMaker endpoint config exists
    #And: 'KmsKeyId' is not specified for the Amazon SageMaker Endpoint Config
    def test_scenario_3_no_kms_present(self):

        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario3})
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario3)
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config = MagicMock(side_effect=self.described_endpoints_scenario3)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'endpoint1', annotation="No AWS KMS Key is configured for this Amazon SageMaker Endpoint Config."))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'endpoint2', annotation="No AWS KMS Key is configured for this Amazon SageMaker Endpoint Config."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_4_no_matching_keyids(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario4})
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario4)
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config = MagicMock(side_effect=self.described_endpoints_scenario4)
        resp_expected = []
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'endpoint1', annotation="AWS KMS Key configured for this Amazon SageMaker Endpoint Config is not an KMS Key allowed in the rule parameter (keyIds)"))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'endpoint2', annotation="AWS KMS Key configured for this Amazon SageMaker Endpoint Config is not an KMS Key allowed in the rule parameter (keyIds)"))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_5_compliant(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario5})
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config = MagicMock(side_effect=self.described_endpoints_scenario5)
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario5)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'endpoint1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'endpoint2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_6_compliant(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario6})
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config = MagicMock(side_effect=self.described_endpoints_scenario6)
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario6)
        resp_expected = []
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected.append(build_expected_response('COMPLIANT', 'endpoint1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'endpoint2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

class ParametersTest(unittest.TestCase):
    rule_parameters_scenario1 = '{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d, arn:als:kms:us-east-1:305333956852:keys/ae25566a-c0d4-4ed2-8131-7c98e9487e3d"}'

    def test_scenario1(self):
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario1)
        response = RULE.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', customer_error_message='The KMS Key id should be in the right format.')

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
