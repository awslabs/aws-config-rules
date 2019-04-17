import sys
import unittest
from datetime import datetime, timedelta
from dateutil import parser
import json

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
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

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

rule = __import__('AMI_OUTDATED_CHECK')

class ComplianceTest(unittest.TestCase):

    #rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'
    invoking_event_ec2_instance = '{"configurationItem":{"configuration":{"instanceId": "i-03402838daac1d611", "imageId": "ami-22ce4934", }, "awsAccountId":"123456789012", "configurationItemStatus":"ResourceDiscovered", "resourceType":"AWS::EC2::Instance", "resourceId":"i-03402838daac1d611", "resourceName":"some-resource-name", "ARN":"some-arn"}, "notificationCreationTime":"2018-07-02T23:05:34.445Z", "messageType":"ConfigurationItemChangeNotification"}'

    describe_instances_old_ami = {"Reservations": [{"Instances": [{"ImageId": "ami-12345678", "InstanceId": "i-12345678" }] }] }
    describe_images_old_ami = {"Images": [{"CreationDate": "2017-08-11T03:41:10.000Z","ImageId": "ami-12345678"}] }

    describe_instances_fresh_ami = {"Reservations": [{"Instances": [{"ImageId": "ami-87654321", "InstanceId": "i-87654321" }] }] }
    describe_images_fresh_ami = {"Images": [{"CreationDate": "2018-08-11T03:41:10.000Z","ImageId": "ami-87654321"}] }

    valid_params = '{"WhitelistedAmis": "", "WhitelistedInstances": "", "NumberOfDays": 60}'
    valid_params_default_days_old = '{"WhitelistedAmis": "", "WhitelistedInstances": "", "NumberOfDays": ""}'
    valid_params_whitelisted_image = '{"WhitelistedAmis": "ami-12345678", "WhitelistedInstances": "", "NumberOfDays": 60}'
    valid_params_whitelisted_instance = '{"WhitelistedAmis": "", "WhitelistedInstances": "i-12345678", "NumberOfDays": 60}'
    invalid_param_missing_image_whitelist = '{"WhitelistedInstances": "i-12345678", "NumberOfDays": 60}'
    invalid_param_missing_instance_whitelist = '{"WhitelistedAmis": "ami-045ceb7b", "NumberOfDays": 60}'
    invalid_param_missing_days_old = '{"WhitelistedAmis": "ami-045ceb7b", "WhitelistedInstances": "i-12345678"}'
    invalid_param_nonnumeric_days_old = '{"WhitelistedAmis": "ami-045ceb7b", "WhitelistedInstances": "i-12345678", "NumberOfDays": "sixty"}'
    invalid_param_days_old_too_low = '{"WhitelistedAmis": "ami-045ceb7b", "WhitelistedInstances": "i-12345678", "NumberOfDays": -60}'
    invalid_param_malformed_image_whitelist = '{"WhitelistedAmis": "image-2", "WhitelistedInstances": "i-12345678", "NumberOfDays": 60}'
    invalid_param_malformed_instance_whitelist = '{"WhitelistedAmis": "ami-045ceb7b", "WhitelistedInstances": "MyServer", "NumberOfDays": 60}'

    def setUp(self):
        #Set the creation_date for our "fresh image" describe_images mock call.
        old_creation_date = parser.parse(self.describe_images_fresh_ami['Images'][0]['CreationDate'])
        current_date = datetime.now(old_creation_date.tzinfo)
        elapsed_time = timedelta(days=1)
        new_creation_date = current_date - elapsed_time
        self.describe_images_fresh_ami['Images'][0]['CreationDate'] = new_creation_date.isoformat()
        print(new_creation_date)

        pass

    #Scenario 1
    def test_parameters_missing_image_whitelist(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_missing_image_whitelist), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    def test_parameters_missing_instance_whitelist(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_missing_instance_whitelist), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    def test_parameters_missing_days_old(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_missing_days_old), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    #Scenario 2
    def test_parameters_nonnumeric_days_old(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_nonnumeric_days_old), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    #Scenario 3
    def test_parameters_days_old_too_low(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_days_old_too_low), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    #Scenario 4
    def test_parameters_malformed_ami_whitelist(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_malformed_image_whitelist), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    #Scenario 5
    def test_parameters_malformed_instance_whitelist(self):
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(self.invalid_param_malformed_instance_whitelist), {})
        assert_customer_error(self, response, "InvalidParameterValueException")

    #Scenario 6
    def test_default_days_old_with_fresh_image(self):
        rule.ASSUME_ROLE_MODE = False
        ec2_client_mock.describe_instances = MagicMock(return_value=self.describe_instances_fresh_ami)
        ec2_client_mock.describe_images = MagicMock(return_value=self.describe_images_fresh_ami)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params_default_days_old), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'i-87654321',
                'AWS::EC2::Instance',
                'AMI is less than 90 days old.'))

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 7
    def test_default_days_old_with_old_image(self):
        rule.ASSUME_ROLE_MODE = False
        ec2_client_mock.describe_instances = MagicMock(return_value=self.describe_instances_old_ami)
        ec2_client_mock.describe_images = MagicMock(return_value=self.describe_images_old_ami)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params_default_days_old), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'i-12345678',
                'AWS::EC2::Instance',
                'The AMI is older than 90 days.'))

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 8
    def test_specified_days_old_with_old_image(self):
        rule.ASSUME_ROLE_MODE = False
        ec2_client_mock.describe_instances = MagicMock(return_value=self.describe_instances_old_ami)
        ec2_client_mock.describe_images = MagicMock(return_value=self.describe_images_old_ami)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'NON_COMPLIANT',
                'i-12345678',
                'AWS::EC2::Instance',
                'The AMI is older than 60 days.'))

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 9
    def test_specified_days_old_with_fresh_image(self):
        rule.ASSUME_ROLE_MODE = False
        ec2_client_mock.describe_instances = MagicMock(return_value=self.describe_instances_fresh_ami)
        ec2_client_mock.describe_images = MagicMock(return_value=self.describe_images_fresh_ami)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'i-87654321',
                'AWS::EC2::Instance',
                'AMI is less than 60 days old.'))

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 10
    def test_whitelisted_image(self):
        rule.ASSUME_ROLE_MODE = False
        ec2_client_mock.describe_instances = MagicMock(return_value=self.describe_instances_old_ami)
        ec2_client_mock.describe_images = MagicMock(return_value=self.describe_images_old_ami)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params_whitelisted_image), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'i-12345678',
                'AWS::EC2::Instance',
                'ImageId in AMI Whitelist'))

        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 11
    def test_whitelisted_instance(self):
        rule.ASSUME_ROLE_MODE = False
        ec2_client_mock.describe_instances = MagicMock(return_value=self.describe_instances_old_ami)
        ec2_client_mock.describe_images = MagicMock(return_value=self.describe_images_old_ami)
        response = rule.lambda_handler(build_lambda_scheduled_event(self.valid_params_whitelisted_instance), {})
        resp_expected = []
        resp_expected.append(
            build_expected_response(
                'COMPLIANT',
                'i-12345678',
                'AWS::EC2::Instance',
                'InstanceId in Instance Whitelist'))
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

def build_lambda_scheduled_event(rule_parameters):
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

#Use this one if we don't needto validate the exact error verbiage.
def assert_customer_error(testClass, response, customerErrorCode):
    assert_customer_error_response(testClass, response, customerErrorCode, response["customerErrorMessage"])

def assert_customer_error_response(testClass, response, customerErrorCode, customerErrorMessage):
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
    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'
    valid_params = '{"WhitelistedAmis": "", "WhitelistedInstances": "", "NumberOfDays": 60}'
    def test_sts_unknown_error(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, self.valid_params), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, self.valid_params), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
