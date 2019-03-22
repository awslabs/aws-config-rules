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
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::User'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
iam_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_PERMISSION_BOUNDARY_CHECK')

class Scenario_3_to_7(unittest.TestCase):
    user_list = {'Users': [
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XM',
             'UserName': 'user-name-1'},
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XN',
             'UserName': 'user-name-2'}]}
    def construct_PermissionList(self, UserName):
        user_info_list = {
    "User": {
        "UserName": "user-name-1", 
        "PermissionsBoundary": {
            "PermissionsBoundaryType": "Policy", 
            "PermissionsBoundaryArn": "arn:aws:iam::aws:policy/AlexaForBusinessDeviceSetup"
        }, 
        "UserId": "AIDAJDTYJDDPUWJ7IR3G2",
        "Arn": "arn:aws:iam::677885075477:user/ddbtest"
    }
}
        return user_info_list
    
    def test_Scenario_3_Non_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.get_user = MagicMock(return_value={'User':{}})
        lambda_event = build_lambda_scheduled_event()
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_Scenario_4_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.get_user = MagicMock(side_effect=self.construct_PermissionList)
        lambda_event = build_lambda_scheduled_event()
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_Scenario_5_With_Parameter_Non_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.get_user = MagicMock(return_value={'User':{}})
        ruleParam = "{\"PermissionBoundaryName\":\"AlexaForBusinessDeviceSetup\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_Scenario_7_With_Parameter_Compliant_User(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.get_user = MagicMock(side_effect=self.construct_PermissionList)
        ruleParam = "{\"PermissionBoundaryName\":\"AlexaForBusinessDeviceSetup,AlexaForBusinessDeviceSetup\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XM'))
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAIDFOUX2OSRO6DO7XN'))
        assert_successful_evaluation(self, response, resp_expected, 2)

class Scenario_TestInvalidPermissionBoundry(unittest.TestCase):
    user_list = {'Users': [
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XM',
             'UserName': 'user-name-1'},
            {'UserId': 'AIDAIDFOUX2OSRO6DO7XN',
             'UserName': 'user-name-2'}]}
             
    def test_Scenario_7_With_Parameter_Incorrect_Policy(self):
        iam_client_mock.list_users = MagicMock(return_value=self.user_list)
        iam_client_mock.get_user = MagicMock(return_value={'User':{}})
        ruleParam = "{\"PermissionBoundaryName\":\"AlexaForBusi??nessDeviceSetup\"}"
        lambda_event = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')
        
class SampleTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        pass

    def test_sample(self):
        self.assertTrue(True)

    #def test_sample_2(self):
    #    rule.ASSUME_ROLE_MODE = False
    #    response = rule.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, self.rule_parameters), {})
    #    resp_expected = []
    #    resp_expected.append(build_expected_response('NOT_APPLICABLE', 'some-resource-id', 'AWS::IAM::Role'))
    #    assert_successful_evaluation(self, response, resp_expected)

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
