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
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::Role'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
STS_SESSION_MOCK = MagicMock()
STS_REGION = None
STS_ACTIVE_REGIONS = ['ap-northeast-1', 'ap-northeast-2', 'ap-south-1']

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK

        raise Exception("Attempting to create an unknown client")

    @staticmethod
    def Session(region_name=None):
        global STS_REGION
        STS_REGION = region_name

        return STS_SESSION_MOCK

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('STS_ENABLE_IN_REGIONS')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def test_scenario_1_activated_regions(self):
        """Test scenario to test there are the same number of active and allowed regions.
        Keyword arguments:
        self -- class ComplianceTest
        """
        global STS_ACTIVE_REGIONS
        STS_ACTIVE_REGIONS = ['ca-central-1', 'eu-central-1', 'eu-west-1']
        sts_mock()
        region_list_mock()
        rule_param = '{"account_id":"264683526309", "role":"sts-mock", "active_regions":"ca-central-1,eu-central-1,eu-west-1"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario_2_activated_regions(self):
        """Test scenario to test there are more active regions then specified.
        Keyword arguments:
        self -- class ComplianceTest
        """
        global STS_ACTIVE_REGIONS
        STS_ACTIVE_REGIONS = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
        sts_mock()
        region_list_mock()
        rule_param = '{"account_id":"264683526309", "role":"sts-mock", "active_regions":"us-east-2,us-west-1"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012'))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_scenario_3_activated_regions(self):
        """Test scenario to test there are more active regions then specified.
        Keyword arguments:
        self -- class ComplianceTest
        """
        global STS_ACTIVE_REGIONS
        STS_ACTIVE_REGIONS = ['ap-northeast-2', 'ap-south-1']
        sts_mock()
        region_list_mock()
        rule_param = '{"account_id":"264683526309", "role":"sts-mock", "active_regions":"us-east-1,ap-northeast-2,ap-south-1,ap-southeast-1,ap-southeast-2"}'
        lambda_event = build_lambda_scheduled_event(rule_parameters=rule_param)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012'))
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

def sts_assume_role(RoleArn, RoleSessionName, DurationSeconds, *args):
    if STS_REGION in STS_ACTIVE_REGIONS:
        return {
            "Credentials": {
                "AccessKeyId": "string",
                "SecretAccessKey": "string",
                "SessionToken": "string"}}

    raise RuntimeError('access denied')

def sts_mock():
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=sts_assume_role)

def region_list_mock():
    response = ['ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2',
                'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1',
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
    STS_SESSION_MOCK.reset_mock(return_value=True)
    STS_SESSION_MOCK.get_available_regions = MagicMock(return_value=response)
    STS_SESSION_MOCK.client = MagicMock(return_value=STS_CLIENT_MOCK)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'RegionDisabledException', 'Message': 'when calling the AssumeRole operation'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')
