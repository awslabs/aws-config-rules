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
DEFAULT_RESOURCE_TYPE = 'AWS::CloudFront::Distribution'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('CLOUDFRONT_VIEWER_POLICY_HTTPS')

class ComplianceTest(unittest.TestCase):

    resource_id = ['E0123456789012', 'E1234567891234', 'E234567890123']

    configurations = [{'distributionConfig':{'cacheBehaviors':{'quantity':2, 'items':[{'viewerProtocolPolicy':'allow-all', 'pathPattern':'images/*.jpg'}, {'viewerProtocolPolicy':'allow-all', 'pathPattern':'videos/*.mp4'}]}, 'defaultCacheBehavior': {'viewerProtocolPolicy':'redirect-to-https'}}}, {'distributionConfig':{'cacheBehaviors':{'quantity':0}, 'defaultCacheBehavior':{'viewerProtocolPolicy':'allow-all'}}}, {'distributionConfig':{'cacheBehaviors':{'quantity':0}, 'defaultCacheBehavior':{'viewerProtocolPolicy':'redirect-to-https'}}}]

    #Gerkin Scenario 1: Default viewer protocol policy is set to 'allow-all'
    def test_scenario1(self):
        invoking_event = construct_invoking_event(self.configurations[1], self.resource_id[1])
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'E1234567891234', 'AWS::CloudFront::Distribution', annotation='''Default ViewerProtocolPolicy is set to 'allow-all' for this Amazon CloudFront distribution.'''))
        assert_successful_evaluation(self, response, resp_expected)

    #Gerkin Scenario 2: Viewer protocol policy of custom cache behavior is set to 'allow-all'
    def test_scenario2(self):
        invoking_event = construct_invoking_event(self.configurations[0], self.resource_id[0])
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'E0123456789012', 'AWS::CloudFront::Distribution', annotation='''ViewerProtocolPolicy for CacheBehavior with path pattern "images/*.jpg" is set to 'allow-all.' '''))
        assert_successful_evaluation(self, response, resp_expected)

    #Gerkin Scenario 3: COMPLIANT
    def test_scenario3(self):
        invoking_event = construct_invoking_event(self.configurations[2], self.resource_id[2])
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'E234567890123', 'AWS::CloudFront::Distribution'))
        assert_successful_evaluation(self, response, resp_expected)

def construct_invoking_event(config, resource_id):
    config_item = {
        'relatedEvents': [],
        'relationships': [],
        'configuration': config,
        'configurationItemVersion': None,
        'configurationItemCaptureTime': "2019-03-17T03:37:52.418Z",
        'supplementaryConfiguration': {},
        'configurationStateId': 1532049940079,
        'awsAccountId': "SAMPLE",
        'configurationItemStatus': "ResourceDiscovered",
        'resourceType': "AWS::CloudFront::Distribution",
        'resourceId': resource_id,
        'resourceName': "hey",
        'awsRegion': "ap-south-1",
        'configurationStateMd5Hash': "",
        'resourceCreationTime': "2019-03-17T06:27:28.289Z",
        'tags': {}
    }
    invoking_event = {
        "configurationItemDiff": "",
        "configurationItem": config_item,
        "notificationCreationTime": "SAMPLE",
        "messageType": "ConfigurationItemChangeNotification",
        "recordVersion": "SAMPLE"
    }
    return invoking_event

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': json.dumps(invoking_event),
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
