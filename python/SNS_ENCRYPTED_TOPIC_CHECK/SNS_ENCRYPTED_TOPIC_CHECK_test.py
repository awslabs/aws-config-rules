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
DEFAULT_RESOURCE_TYPE = 'AWS::SNS::Topic'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
SNS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'sns':
            return SNS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('SNS_ENCRYPTED_TOPIC_CHECK')

class InvalidRuleParameter(unittest.TestCase):

    def test_scenario_1_error(self):
        list_topics_result = {"Topics": [{"TopicArn": "arn:aws:sns:ap-southeast-1:123456789012:testSNS"}]}

        get_topic_attributes_result = {
            "Attributes": {
                "KmsMasterKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/86a9f691-c02f-4046-9360-903afec68edc"
            }}

        SNS_CLIENT_MOCK.list_topics = MagicMock(return_value=list_topics_result)
        SNS_CLIENT_MOCK.get_topic_attributes = MagicMock(return_value=get_topic_attributes_result)
        rule_parameters = '{"KmsKeyId": "99a9f661-c02f-4046-9360-9334dex68gdc"}'
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters), {})
        assert_customer_error_response(
            self,
            lambda_result,
            'InvalidParameterValueException',
            'Invalid value for the parameter "KmsKeyId", expected valid ARN(s) of Kms Key'
        )

class NotApplicable(unittest.TestCase):

    def test_scenario_2_not_applicable(self):
        list_topics_result = {"Topics": []}

        get_topic_attributes_result = {}

        SNS_CLIENT_MOCK.list_topics = MagicMock(return_value=list_topics_result)
        SNS_CLIENT_MOCK.get_topic_attributes = MagicMock(return_value=get_topic_attributes_result)
        rule_parameters = '{"KmsKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/99a9f661-c02f-4046-9360-9334dex68gdc"}'
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters), {})
        expected_response = [build_expected_response("NOT_APPLICABLE", '123456789012', 'AWS::::Account')]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

class NonCompliantResourcesTest(unittest.TestCase):

    def test_scenario_3_non_compliant_resources_without_key(self):
        list_topics_result = {"Topics": [{"TopicArn": "arn:aws:sns:ap-southeast-1:123456789012:dynamodbtopic"}]}

        get_topic_attributes_result = {"Attributes": {}}

        SNS_CLIENT_MOCK.list_topics = MagicMock(return_value=list_topics_result)
        SNS_CLIENT_MOCK.get_topic_attributes = MagicMock(return_value=get_topic_attributes_result)
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event({}), {})
        expected_response = [build_expected_response(
            'NON_COMPLIANT',
            'arn:aws:sns:ap-southeast-1:123456789012:dynamodbtopic',
            annotation="The Amazon Simple Notification Service topic is not encrypted."
        )]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

    def test_scenario_5_non_compliant_resources_with_key(self):
        list_topics_result = {"Topics": [{"TopicArn": "arn:aws:sns:ap-southeast-1:123456789012:testSNS"}]}

        get_topic_attributes_result = {
            "Attributes": {
                "KmsMasterKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/86a9f691-c02f-4046-9360-903afec68edc"
            }}

        SNS_CLIENT_MOCK.list_topics = MagicMock(return_value=list_topics_result)
        SNS_CLIENT_MOCK.get_topic_attributes = MagicMock(return_value=get_topic_attributes_result)
        rule_parameters = '{"KmsKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/99a9f661-c02f-4046-9360-9334dex68gdc"}'
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters), {})
        expected_response = [build_expected_response(
            'NON_COMPLIANT',
            'arn:aws:sns:ap-southeast-1:123456789012:testSNS',
            annotation="This SNS topic is not encrypted with KMS Key {KmsKeyId}: ['arn:aws:kms:ap-southeast-1:123456789012:key/99a9f661-c02f-4046-9360-9334dex68gdc']"
        )]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

class CompliantResourcesTest(unittest.TestCase):

    def test_scenario_4_compliant_resources_without_key(self):
        list_topics_result = {"Topics": [{"TopicArn":"arn:aws:sns:ap-southeast-1:123456789012:testSNS"}]}

        get_topic_attributes_result = {
            "Attributes": {
                "KmsMasterKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/86a9f691-c02f-4046-9360-903afec68edc"
            }}

        SNS_CLIENT_MOCK.list_topics = MagicMock(return_value=list_topics_result)
        SNS_CLIENT_MOCK.get_topic_attributes = MagicMock(return_value=get_topic_attributes_result)
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event({}), {})
        expected_response = [build_expected_response(
            'COMPLIANT',
            'arn:aws:sns:ap-southeast-1:123456789012:testSNS'
        )]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

    def test_scenario_6_compliant_resources_with_key(self):
        list_topics_result = {"Topics": [{"TopicArn": "arn:aws:sns:ap-southeast-1:123456789012:testSNS"}]}

        get_topic_attributes_result = {
            "Attributes": {
                "KmsMasterKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/86a9f691-c02f-4046-9360-903afec68edc"
            }}

        SNS_CLIENT_MOCK.list_topics = MagicMock(return_value=list_topics_result)
        SNS_CLIENT_MOCK.get_topic_attributes = MagicMock(return_value=get_topic_attributes_result)
        rule_parameters = '{"KmsKeyId": "arn:aws:kms:ap-southeast-1:123456789012:key/86a9f691-c02f-4046-9360-903afec68edc"}'
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters), {})
        expected_response = [build_expected_response(
            'COMPLIANT',
            'arn:aws:sns:ap-southeast-1:123456789012:testSNS'
        )]
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
