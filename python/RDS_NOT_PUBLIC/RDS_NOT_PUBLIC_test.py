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
import json
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::RDS::DBInstance'

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

rule = __import__('RDS_NOT_PUBLIC')

class TestDBInstanceForCompliance(unittest.TestCase):

    #SCENARIO 1: RDS is in 'Publicly Accessible' mode
    def test_Scenario_1_noncompliant_instance_publicly_accessible(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("available", True)
        response = rule.lambda_handler(build_lambda_configurationchange_event(json.dumps(invoking_event)), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'db-SYCP3PPQ2ZEKCS5SB4TFBQRL6I'))
        assert_successful_evaluation(self, response, resp_expected)

    #SCENARIO 2: RDS is not in 'Publicly Accessible' mode
    def test_Scenario_2_compliant_instance_not_publicly_accessible(self):
        rule.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event("available", False)
        response = rule.lambda_handler(build_lambda_configurationchange_event(json.dumps(invoking_event)), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'db-SYCP3PPQ2ZEKCS5SB4TFBQRL6I'))
        assert_successful_evaluation(self, response, resp_expected)


def build_invoking_event(db_status, is_publicly_accessible):
    configuration_item = build_configuration_item(db_status, is_publicly_accessible)
    return {
        "messageType": "ConfigurationItemChangeNotification",
        "configurationItem": configuration_item
    }

def build_configuration_item(db_status, is_publicly_accessible):
    configuration = {
        "dBInstanceIdentifier": "rdsinstance",
        "dBInstanceStatus": db_status,
        "dBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:rdsinstance",
        "publiclyAccessible": is_publicly_accessible}

    configuration_item = {
        "awsAccountId": '125476540976',
        "configurationItemCaptureTime": "2018-07-19T17:22:05.874Z",
        "configurationItemStatus": "OK",
        "arn": "arn:aws:rds:us-east-1:123456789012:db:rdsinstance",
        "resourceType": "AWS::RDS::DBInstance",
        "resourceId": "db-SYCP3PPQ2ZEKCS5SB4TFBQRL6I",
        "resourceName": "rdsinstance",
        "awsRegion": 'us-east-1',
        "configuration": configuration}

    return configuration_item

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
