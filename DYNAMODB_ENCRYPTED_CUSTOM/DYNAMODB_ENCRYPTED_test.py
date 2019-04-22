#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import sys
import json
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
DEFAULT_RESOURCE_TYPE = 'AWS::DynamoDB::Table'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('DYNAMODB_ENCRYPTED')

class TestDynamoDbTablesForCompliance(unittest.TestCase):

    def test_Scenario_3_not_applicable_deleted(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("DELETED", False)
        invoking_event['configurationItem']['configurationItemStatus'] = "ResourceDeleted"
        response = rule.lambda_handler(build_lambda_configurationchange_event(json.dumps(invoking_event)), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'config-test-table'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_3_not_applicable_table_deleting(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("DELETING", False)
        response = rule.lambda_handler(build_lambda_configurationchange_event(json.dumps(invoking_event)), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'config-test-table'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_5_noncompliant_table_active_and_non_encrypted(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("ACTIVE", False)
        response = rule.lambda_handler(build_lambda_configurationchange_event(json.dumps(invoking_event)), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'config-test-table', annotation='The DynamoDB table "config-test-table" is not encrypted.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_4_compliant_table_active_and_encrypted(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("ACTIVE", True)
        response = rule.lambda_handler(build_lambda_configurationchange_event(json.dumps(invoking_event)), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'config-test-table'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_2_compliant_table_whitelisted_non_encrypted(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("ACTIVE", False)
        invoking_event['configurationItem']['resourceId'] = 'whitelisted-id'
        rule_parameters = '{"WhitelistedTables":"whitelisted-id"}'
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(
                json.dumps(invoking_event), rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'whitelisted-id', annotation='The DynamoDB table "whitelisted-id" is whitelisted.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_2_compliant_table_whitelisted_encrypted(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("ACTIVE", True)
        invoking_event['configurationItem']['resourceId'] = 'whitelisted-id'
        rule_parameters = '{"WhitelistedTables":"whitelisted-id"}'
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(
                json.dumps(invoking_event), rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'whitelisted-id', annotation='The DynamoDB table "whitelisted-id" is whitelisted.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_1_invalid_key_parameters(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("ACTIVE", True)
        rule_parameters = '{"WhitelistedTables":"whitelisted-id", "invalid":"invalid"}'
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(
                json.dumps(invoking_event), rule_parameters), {})
        assert_customer_error_response(
            self,
            response,
            'InvalidParameterValueException',
            "The parameter ({'WhitelistedTables': 'whitelisted-id', 'invalid': 'invalid'}) has more than one key. The only accepted key is: WhitelistedTables.")

    def test_Scenario_1_invalid_parameter(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("ACTIVE", True)
        rule_parameters = '{"invalid":"invalid"}'
        response = rule.lambda_handler(
            build_lambda_configurationchange_event(
                json.dumps(invoking_event), rule_parameters), {})
        assert_customer_error_response(
            self,
            response,
            'InvalidParameterValueException',
            "The parameter ({'invalid': 'invalid'}) has not a valid key.")

def build_invoking_event(table_status, sse_enabled):
    configuration_item = build_configuration_item(table_status, sse_enabled)
    return {
        "messageType": "ConfigurationItemChangeNotification",
        "configurationItem": configuration_item
    }

def build_configuration_item(table_status, sse_enabled):
    configuration = {
        "tableStatus": table_status,
        "tableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/config-test-table"}

    if sse_enabled:
        configuration["ssedescription"] = {
            "status": "ENABLED"
        }

    configuration_item = {
        "awsAccountId": '123456789012',
        "configurationItemCaptureTime": "2018-02-28T11:22:05.874Z",
        "configurationItemStatus": "ResourceDiscovered",
        "arn": "arn:aws:dynamodb:us-east-1:920520484730:table/config-test-table",
        "resourceType": "AWS::DynamoDB::Table",
        "resourceId": "config-test-table",
        "resourceName": "config-test-table",
        "awsRegion": 'us-east-1',
        "configuration": configuration}
    return configuration_item

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    sts_client_mock.reset_mock(return_value=True)
    sts_client_mock.assume_role = MagicMock(return_value=assume_role_response)

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

##################
# Commun Testing #
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