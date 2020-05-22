#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#

import json
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
EC2_CLIENT_MOCK = MagicMock()


class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'ec2':
            return EC2_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")


sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EBS_DEFAULT_ENCRYPTION_ENABLED')


class ComplianceTest(unittest.TestCase):

    ec2_ebs_encrypted_setting = {"EbsEncryptionByDefault": True}
    ec2_ebs_unencrypted_setting = {"EbsEncryptionByDefault": False}

    def test_ec2_ebs_encrypted(self):
        '''
        Test that EBS is encrypted with a KMS key in general, no KmsKeyId optional parameter provided
        COMPLIANT if encryption enabled, regardless of key
        '''
        default_ebs_key = "alias/aws/ebs"
        EC2_CLIENT_MOCK.get_ebs_encryption_by_default = MagicMock(
            return_value=self.ec2_ebs_encrypted_setting)
        EC2_CLIENT_MOCK.get_ebs_default_kms_key_id = MagicMock(
            return_value={"KmsKeyId": default_ebs_key})
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                '123456789012',
                DEFAULT_RESOURCE_TYPE,
                annotation=f'EC2 EBS Encryption setting default KMS key is: {default_ebs_key}'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_ec2_ebs_encrypted_incorrect_key(self):
        '''
        Test that EBS is encrypted with a KMS key that matches the KmsKeyId optional parameter provided
        NON_COMPLIANT if keys do not match
        '''
        parameter_kms_key = "alias/aws/ebs"
        current_kms_key = "alias/random/key"
        EC2_CLIENT_MOCK.get_ebs_encryption_by_default = MagicMock(
            return_value=self.ec2_ebs_encrypted_setting)
        EC2_CLIENT_MOCK.get_ebs_default_kms_key_id = MagicMock(
            return_value={"KmsKeyId": current_kms_key})
        response = RULE.lambda_handler(build_lambda_scheduled_event(
            json.dumps({"KmsKeyId": parameter_kms_key})), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                '123456789012',
                DEFAULT_RESOURCE_TYPE,
                annotation=f'Expected default key {parameter_kms_key} but is currently {current_kms_key}'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_ec2_ebs_encrypted_correct_key(self):
        '''
        Test that EBS is encrypted with a KMS key that matches the KmsKeyId optional parameter provided
        COMPLIANT if keys match
        '''
        parameter_kms_key = "alias/aws/ebs"
        current_kms_key = parameter_kms_key
        EC2_CLIENT_MOCK.get_ebs_encryption_by_default = MagicMock(
            return_value=self.ec2_ebs_encrypted_setting)
        EC2_CLIENT_MOCK.get_ebs_default_kms_key_id = MagicMock(
            return_value={"KmsKeyId": current_kms_key})
        response = RULE.lambda_handler(build_lambda_scheduled_event(
            json.dumps({"KmsKeyId": parameter_kms_key})), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                '123456789012',
                DEFAULT_RESOURCE_TYPE,
                annotation=f'EC2 EBS Encryption setting default KMS key is: {current_kms_key}'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_ec2_ebs_unencrypted(self):
        '''
        Test that EBS is encrypted with a KMS key in general, no KmsKeyId optional parameter provided
        NON_COMPLIANT if encryption not enabled, regardless of key
        '''
        EC2_CLIENT_MOCK.get_ebs_encryption_by_default = MagicMock(
            return_value=self.ec2_ebs_unencrypted_setting)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                '123456789012',
                DEFAULT_RESOURCE_TYPE))
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
        test_class.assertEquals(
            resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(
            resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(
            resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(
                resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(
                response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(
                response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(
                response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(
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
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
