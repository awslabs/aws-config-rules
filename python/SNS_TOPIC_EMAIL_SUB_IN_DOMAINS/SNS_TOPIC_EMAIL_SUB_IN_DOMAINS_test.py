import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

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

RULE = __import__('SNS_TOPIC_EMAIL_SUB_IN_DOMAINS')

class SampleTest(unittest.TestCase):


    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        pass

    def test_scenario1(self):
        SNS_CLIENT_MOCK.list_subscriptions = MagicMock(return_value={"Subscriptions":[]})
        rule_param = "{\"domainNames\":\"gmailcom,notyourwish.net,merachelega.org\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', customer_error_message='gmailcom not a valid domain name.')

    def test_scenario2(self):
        SNS_CLIENT_MOCK.list_subscriptions = MagicMock(return_value={"Subscriptions":[]})
        rule_param = "{\"domainNames\":\"gmail.com,notyourwish.net,merachelega.org\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario3(self):
        SNS_CLIENT_MOCK.list_subscriptions = MagicMock(return_value={"Subscriptions":[]})
        rule_param = "{\"domainNames\":\"\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', customer_error_message='At least one domain name is required as input parameter.')

    def test_scenario4(self):
        SNS_CLIENT_MOCK.list_subscriptions = MagicMock(return_value={"Subscriptions":[{
            "Owner": "123456789012",
            "Endpoint": "abc@gmail.com",
            "Protocol": "email",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:vrvamshi47email",
            "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:vrvamshi47email:2c87e66f-b659-48ed-9d3b-84f65a5510cc"
        }]})
        rule_param = "{\"domainNames\":\"gmail1.com,notyourwish.net,merachelega.org\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:sns:us-east-1:123456789012:vrvamshi47email:abc@gmail.com', 'AWS::SNS::Topic', annotation='Endpoint domain is not in the provided input domain names.'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario5(self):
        SNS_CLIENT_MOCK.list_subscriptions = MagicMock(return_value={"Subscriptions":[{
            "Owner": "123456789012",
            "Endpoint": "abc@gmail.com",
            "Protocol": "email",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:vrvamshi47email",
            "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:vrvamshi47email:2c87e66f-b659-48ed-9d3b-84f65a5510cc"
        }]})
        rule_param = "{\"domainNames\":\"gmail.com,notyourwish.net,merachelega.org\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:sns:us-east-1:123456789012:vrvamshi47email:abc@gmail.com', 'AWS::SNS::Topic'))
        assert_successful_evaluation(self, response, resp_expected, 1)

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
    