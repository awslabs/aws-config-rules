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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
ct_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'cloudtrail':
            return ct_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('CLOUDTRAIL_ENABLED_V2')

class ComplianceTest(unittest.TestCase):

    rule_parameters_s3_bucket = '{"S3BucketName":"some-bucket-name"}'
    rule_parameters_encryption = '{"EncryptedBoolean":"True", "KMSKeyArn":"some-key-arn"}'
    rule_parameters_global = '{"GlobalResourcesBoolean":"True"}'
    rule_parameters_multi = '{"MultiRegionBoolean":"True"}'
    rule_parameters_mgmt = '{"ManagementEventBoolean":"True"}'
    rule_parameters_s3_event = '{"S3DataEventBoolean":"True"}'
    rule_parameters_lambda_event = '{"LambdaEventBoolean":"True"}'
    rule_parameters_lfi = '{"LFIBoolean":"True"}'
    rule_parameters_all = '{"S3BucketName":"some-bucket-name", "EncryptedBoolean":"True", "KMSKeyArn":"some-key-arn", "GlobalResourcesBoolean":"True", "MultiRegionBoolean":"True", "ManagementEventBoolean":"True", "S3DataEventBoolean":"True", "LambdaEventBoolean":"True", "LFIBoolean":"True"}'

    describe_trail_none = {'trailList': []}
    describe_trail_valid = {
        'trailList': [{
            'Name': 'ct-name-1',
            'S3BucketName': 'other-name',
            'IncludeGlobalServiceEvents': False,
            'IsMultiRegionTrail': False,
            'LogFileValidationEnabled': False,
            'KmsKeyId': 'some-other-key',
            'HasCustomEventSelectors': False
        }, {
            'Name': 'ct-name-2',
            'S3BucketName': 'cloudtrail-cac-reinvent',
            'IncludeGlobalServiceEvents': False,
            'IsMultiRegionTrail': False,
            'LogFileValidationEnabled': False,
            'HasCustomEventSelectors': False
        }]}    
    describe_trail_valid_no_key = {
        'trailList': [{
            'Name': 'ct-name-1',
        }]}
    describe_trail_all = {
        'trailList': [{
            'Name': 'ct-name-1',
            'S3BucketName': 'some-bucket-name',
            'IncludeGlobalServiceEvents': True,
            'IsMultiRegionTrail': True,
            'LogFileValidationEnabled': True,
            'KmsKeyId': 'some-key-arn',
            'HasCustomEventSelectors': True
        }]}

    get_event_selectors_mgmt_false = {"EventSelectors": [{"IncludeManagementEvents": False}]}
    get_event_selectors_mgmt_notall = {"EventSelectors": [{
            "ReadWriteType": "NotAll",
            "IncludeManagementEvents": True}]}
    get_event_selectors_invalid = {"EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [
                {
                    "Type": "AWS::S3::Object",
                    "Values": ["arn:aws:s3:something"]
                },
                {
                    "Type": "AWS::Lambda::Function",
                    "Values": ["arn:aws:lambda:something"]
                }
            ]
        }
    ]}
    get_event_selectors_all = {"EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": True,
            "DataResources": [
                {
                    "Type": "AWS::S3::Object",
                    "Values": ["arn:aws:s3"]
                },
                {
                    "Type": "AWS::Lambda::Function",
                    "Values": ["arn:aws:lambda"]
                }
            ]
        }
    ]}

    logging = {'IsLogging': True}
    no_logging = {'IsLogging': False}
    failed_delivery = {'IsLogging': True, 'LatestDeliveryError': 'some-error'}

    def test_scenario01_param_not_valid(self):
        rule.ASSUME_ROLE_MODE = False
        for param in ['EncryptedBoolean', 'GlobalResourcesBoolean', 'MultiRegionBoolean', 'ManagementEventBoolean', 'S3DataEventBoolean', 'LambdaEventBoolean', 'LFIBoolean']:
            invalid_param = {}
            invalid_param[param]='invalid'
            response = rule.lambda_handler(build_lambda_scheduled_event(json.dumps(invalid_param)), {})
            assert_customer_error_response(self, response, 'InvalidParameterValueException', 'The parameter "{}" must be either "True" or "False".'.format(param))

    def test_scenario02_no_trail(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_none)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario03_not_enabled(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.no_logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario04_no_delivery_success(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.failed_delivery)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario05_s3_name(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_s3_bucket), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario06_encryption(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_encryption), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario07_encryption_not_same_key(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid_no_key)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_encryption), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario08_global(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_global), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario09_multi(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_multi), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario10_mgmt_false(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        ct_client_mock.get_event_selectors = MagicMock(return_value=self.get_event_selectors_mgmt_false)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_mgmt), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario11_mgmt_noall(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        ct_client_mock.get_event_selectors = MagicMock(return_value=self.get_event_selectors_mgmt_notall)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_mgmt), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario12_s3_event(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        ct_client_mock.get_event_selectors = MagicMock(return_value=self.get_event_selectors_invalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_s3_event), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario13_lambda_event(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        ct_client_mock.get_event_selectors = MagicMock(return_value=self.get_event_selectors_invalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_lambda_event), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario14_lfi(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_valid)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_lfi), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario15_all(self):
        rule.ASSUME_ROLE_MODE = False
        ct_client_mock.describe_trails = MagicMock(return_value=self.describe_trail_all)
        ct_client_mock.get_trail_status = MagicMock(return_value=self.logging)
        ct_client_mock.get_event_selectors = MagicMock(return_value=self.get_event_selectors_all)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.rule_parameters_all), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012', 'AWS::::Account'))
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
