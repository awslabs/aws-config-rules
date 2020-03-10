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
DEFAULT_RESOURCE_TYPE = 'AWS::EFS::FileSystem'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EFS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'efs':
            return EFS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EFS_ENCRYPTED_CHECK')

class ComplianceTestScenarios(unittest.TestCase):

    rule_valid_parameters = '{"KmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/12345-1111-1111-1111-123456789"}'
    rule_invalid_value_parameter = '{"KmsKeyId": "asdfa97asf8a0sf09sa8df0a98sd0f8as0f8d0"}'
    rule_empty_parameter = '{"KmsKeyId": ""}'

    efs_zero_file_system = {
        "FileSystems": [
        ],
    }

    efs_encrypted_matching_key = {
        "FileSystems": [
            {
                "OwnerId": "234759432549",
                "FileSystemId": "fs-123456ab",
                "Encrypted": True,
                "KmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/12345-1111-1111-1111-123456789",
            },
        ],
    }

    efs_encrypted_different_kms_key = {
        "FileSystems": [
            {
                "OwnerId": "234759432549",
                "FileSystemId": "fs-123456ab",
                "Encrypted": True,
                "KmsKeyId": "arn:aws:kms:us-west-2:123456789012:key/12345-1111-1111-1111-00000000",
            },
        ],
    }
    efs_not_encrypted = {
        "FileSystems": [
            {
                "OwnerId": "234759432549",
                "FileSystemId": "fs-123456ab",
                "Encrypted": False,
            },
        ],
    }

    # Common Scenario
    def test_invalid_value_parameter(self):
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_invalid_value_parameter), {})
        assert_customer_error_response(
            self, response, 'InvalidParameterValueException', 'Invalid value for paramter KmsKeyId, Expected KMS Key ARN')

    # Scenarion 1
    def test_efs_zero_file_systems(self):
        EFS_CLIENT_MOCK.describe_file_systems = MagicMock(return_value=self.efs_zero_file_system)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_empty_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 2
    def test_efs_not_encrypted(self):
        EFS_CLIENT_MOCK.describe_file_systems = MagicMock(return_value=self.efs_not_encrypted)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'fs-123456ab', 'AWS::EFS::FileSystem', 'This EFS File System is not encrypted.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 3
    def test_efs_encrypted_no_parameter(self):
        EFS_CLIENT_MOCK.describe_file_systems = MagicMock(return_value=self.efs_encrypted_matching_key)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_empty_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'fs-123456ab', 'AWS::EFS::FileSystem'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4
    def test_efs_encrypted_no_match(self):
        EFS_CLIENT_MOCK.describe_file_systems = MagicMock(return_value=self.efs_encrypted_different_kms_key)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'fs-123456ab', 'AWS::EFS::FileSystem', 'This EFS File System is not encrypted with the KMS key specified in "KmsKeyId" input parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5
    def test_efs_encrypted_valid_param(self):
        EFS_CLIENT_MOCK.describe_file_systems = MagicMock(return_value=self.efs_encrypted_matching_key)
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'fs-123456ab', 'AWS::EFS::FileSystem'))
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
