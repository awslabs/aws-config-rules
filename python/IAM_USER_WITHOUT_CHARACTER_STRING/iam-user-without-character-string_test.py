import sys
import json
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    import mock
    from mock import MagicMock
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
IAM_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'sts':
            return STS_CLIENT_MOCK
        elif client_name == 'iam':
            return IAM_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('iam-user-without-character-string')

class Scenario_1(unittest.TestCase):

    user_list = {'Users': [
        {'UserId': 'AIDAIDFOUX2OSRO6DO7XA',
         'UserName': 'user-name-1'},
        {'UserId': 'AIDAIDFOUX2OSRO6DO7XB',
         'UserName': 'user-name-admin-2'},
        {'UserId': 'AIDAIDFOUX2OSRO6DO7XC',
         'UserName': 'user-name-admin-power-3'},
        {'UserId': 'AIDAIDFOUX2OSRO6DO7XD',
         'UserName': 'Admin-user-name-4'},
        {'UserId': 'AIDAIDFOUX2OSRO6DO7XE',
         'UserName': 'Power-username-5 '}]}

    def test_Scenario_1_Compliant_User(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        ruleParam = '{\"patternLst\":[\"admin\"]}'
        invoking_event = constructInvokingEvent(constructConfigItem(self.user_list['Users'][0]['UserName']))
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', self.user_list['Users'][0]['UserName']))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_Scenario_2_Non_Compliant_User(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        ruleParam = '{\"patternLst\":[\".*admin.*\"]}'
        invoking_event = constructInvokingEvent(constructConfigItem(self.user_list['Users'][1]['UserName']))
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', self.user_list['Users'][1]['UserName']))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_Scenario_3_Non_Compliant_User(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        ruleParam = '{\"patternLst\":[\".*admin.*\",\".*power.*\"]}'
        invoking_event = constructInvokingEvent(constructConfigItem(self.user_list['Users'][2]['UserName']))
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', self.user_list['Users'][2]['UserName']))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_Scenario_4_Non_Compliant_User(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        ruleParam = '{\"patternLst\":[\"[aA]dmin\",\"power\"]}'
        invoking_event = constructInvokingEvent(constructConfigItem(self.user_list['Users'][3]['UserName']))
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', self.user_list['Users'][3]['UserName']))
        assert_successful_evaluation(self, response, resp_expected, 1)

    def test_Scenario_5_Non_Compliant_User(self):
        IAM_CLIENT_MOCK.list_users = MagicMock(return_value=self.user_list)
        ruleParam = '{\"patternLst\":[\"admin\",\"Power\",\"^[A-Z]\\\\w.+\"]}'
        invoking_event = constructInvokingEvent(constructConfigItem(self.user_list['Users'][4]['UserName']))
        lambda_event = build_lambda_configurationchange_event(invoking_event, rule_parameters=ruleParam)
        response = RULE.lambda_handler(lambda_event, {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', self.user_list['Users'][4]['UserName']))
        assert_successful_evaluation(self, response, resp_expected, 1)

####################
# Helper Functions #
####################

def constructConfigItem(resourceName):
    configItem = {
        'relatedEvents': [],
        'relationships': [],
        'configuration': None,
        'configurationItemVersion': None,
        'configurationItemCaptureTime': "2019-03-17T03:37:52.418Z",
        'supplementaryConfiguration': {},
        'configurationStateId': 1532049940079,
        'awsAccountId': "SAMPLE",
        'configurationItemStatus': "ResourceDiscovered",
        'resourceType': "AWS::IAM::User",
        'resourceId': "AIDAILEDWOGIPJFAKOJKW",
        'resourceName': resourceName,
        'ARN': "arn:aws:iam::264683526309:user/{}".format(resourceName),
        'awsRegion': "ap-south-1",
        'configurationStateMd5Hash': "",
        'resourceCreationTime': "2018\9-03-17T06:27:28.289Z",
        'tags': {}
    }
    return configItem

def constructInvokingEvent(configItem):
    invokingEvent = {
    "configurationItemDiff": None,
    "configurationItem": configItem,
    "notificationCreationTime": "SAMPLE",
    "messageType": "ConfigurationItemChangeNotification",
    "recordVersion": "SAMPLE"
    }
    return invokingEvent

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
        event_to_return['ruleParameters'] = json.dumps(rule_parameters)
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