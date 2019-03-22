import sys
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
ec2_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'ec2':
            return ec2_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('AMI_NOT_PUBLIC_CHECK')

# Checks for scenario wherein no non-compliant resources are present
class CompliantResourcesTest(unittest.TestCase):
    lambda_event = {}

    def setUp(self):
        self.lambda_event = build_lambda_scheduled_event()
        pass

    def test_scenario_1_compliant_resources(self):
        describe_images_result = {
                    'Images': [],
                    'ResponseMetadata': {'HTTPStatusCode': 200}
        }
        ec2_client_mock.describe_images = MagicMock(return_value=describe_images_result)
        lambda_result = rule.lambda_handler(self.lambda_event, {})
        expected_response = [
                		build_expected_response(
                    			compliance_type='NOT_APPLICABLE',
                    			compliance_resource_id='N/A',
                    			compliance_resource_type=DEFAULT_RESOURCE_TYPE
                		)
        ]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

# Checks for scenario wherein non-compliant resources are present (Two Public Amazon Machine Image)
class NonCompliantResourcesTest(unittest.TestCase):
    lambda_event = {}

    def setUp(self):
        self.lambda_event = build_lambda_scheduled_event()
        pass

    def test_scenario_2_non_compliant_resources(self):
            describe_images_result = {
                'Images': [
                    {
                      'ImageId': 'ami-040574eaefd6dc6d4',
                      'Public': True,
                      'OwnerId': '123456789012',
                      'State': 'available'
                    },
                    {
                      'ImageId': 'ami-0a1402bb0642906aa',
                      'Public': True,
                      'OwnerId': '123456789012',
                      'State': 'available'
                     }
                ],
                'ResponseMetadata': {'HTTPStatusCode': 200}
            }
            ec2_client_mock.describe_images = MagicMock(return_value=describe_images_result)
            lambda_result = rule.lambda_handler(self.lambda_event, {})
            expected_response = [
                        build_expected_response(
                                compliance_type='NON_COMPLIANT',
                                compliance_resource_id='ami-040574eaefd6dc6d4',
                                compliance_resource_type=DEFAULT_RESOURCE_TYPE,
                                annotation="Amazon Machine Image Id: ami-040574eaefd6dc6d4 is public"
                        ),
                        build_expected_response(
                                compliance_type='NON_COMPLIANT',
                                compliance_resource_id='ami-0a1402bb0642906aa',
                                compliance_resource_type=DEFAULT_RESOURCE_TYPE,
                                annotation="Amazon Machine Image Id: ami-0a1402bb0642906aa is public"
                        )
            ]
            assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

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
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z","awsAccountId":"123456789012"}'
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

