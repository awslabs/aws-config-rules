#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError
import sys
import datetime
import json
from dateutil.tz import tzutc
from datetime import timedelta

config_client_mock = MagicMock()
iam_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'iam':
            return iam_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_USER_USED_LAST_90_DAYS')

def buildLambdaEvent(ruleParameters='{}', invokingEvent={}, scheduled=True):

    if invokingEvent != {}:
        invoking_event = json.dumps(invokingEvent)
    elif scheduled:
        invoking_event = '{"awsAccountId":"112233445566","notificationCreationTime":"2018-03-01T11:21:06.236Z","messageType":"ScheduledNotification","recordVersion":"1.0"}'
    else:
        config_item = {
        "accountId": "112233445566",
        "configurationItemCaptureTime": "2016-11-06T17:56:56.560Z",
        "configurationItemStatus": "OK",
        "configurationStateId": "1478455016560",
        "configurationItemMD5Hash": "0a2aae6878d94cd28a9ec808a10e8402",
        "resourceType": "AWS::IAM::User",
        "resourceId": "AIDAJYPPIFB65RV8YYLDU",
        "resourceName": "user-name",
        "resourceCreationTime": "2016-09-22T05:55:07.000Z",
        "configuration": {
            "userName": "user-name",
            "userId": "AIDAJYPPIFB65RV8YYLDU",
            "arn": "arn:aws:iam::112233445566:user/user-name",
            "createDate": "2016-09-22T05:55:07.000Z"
            }
        }
        
        invoking_event = '{"awsAccountId":"112233445566","messageType":"ConfigurationItemChangeNotification","configurationItem":'+json.dumps(config_item)+'}'

    return {
        'accountId': 'account-id',
        'configRuleArn': 'arn:aws:config:ap-south-1:112233445566:config-rule/config-rule-swb7as',
        'configRuleId': 'config-rule-swb7as',
        'configRuleName': 'iam-user-used-last-90-days',
        'eventLeftScope': False,
        'executionRoleArn': 'arn:aws:iam::112233445566:role/service-role/config-role',
        'invokingEvent': invoking_event,
        'resultToken': 'TESTMODE',
        'ruleParameters': json.dumps(ruleParameters)
        }

def build_expected_response(ComplianceType, ComplianceResourceId, ComplianceResourceType='AWS::IAM::User', Annotation=None):
    if not Annotation:
        return {
            'ComplianceType': ComplianceType,
            'ComplianceResourceId': ComplianceResourceId,
            'ComplianceResourceType': ComplianceResourceType
            }
    return {
        'ComplianceType': ComplianceType,
        'ComplianceResourceId': ComplianceResourceId,
        'ComplianceResourceType': ComplianceResourceType,
        'Annotation': Annotation
        }

def get_user_pwd_days(day=90):
    return {'User': {'PasswordLastUsed': constructDateTime(day)}}

def get_user_access_key_day(day=90):
    return {'AccessKeyLastUsed': {'LastUsedDate': constructDateTime(day)}}

def constructDateTime(expiryTime=90):
    today = datetime.datetime.now(tz=tzutc())
    targetDatetime = today - timedelta(days=expiryTime)
    return targetDatetime

def parameter_catalog(whitelist='', expiry=90):
    if not whitelist:
        if expiry == 90:
            return {}
        return { "NotUsedTimeOutInDays" : expiry } 
    if whitelist:
        if expiry == 90:
            return { "WhitelistedUserList" : whitelist }
        return { 
            "WhitelistedUserList" : whitelist, "NotUsedTimeOutInDays" : expiry
            }
    
class TestUnexpectedNotifications(unittest.TestCase):
     def test_invalid_notification(self):
         response = rule.lambda_handler({'resultToken':'TESTMODE', 'executionRoleArn':'roleArn','eventLeftScope': True,'invokingEvent':'{"messageType":"invalid-type"}','ruleParameters':'{}','accountId':'account-id','configRuleArn':'rule-arn'}, {})
         self.assertEqual(response['internalErrorDetails'], 'Error: messageType is an expected type.')
         self.assertEqual(response['customerErrorMessage'], "InternalError")

class TestInvalidParameters(unittest.TestCase):
    def setUp(self):
        config_client_mock.reset_mock()
        iam_client_mock.reset_mock()

    invalidUserWhiteListParams = {
    "invalidEntry" : [{"WhitelistedUserList":"1234578910"},
                    {"WhitelistedUserList": {'test':'test2'}},
                    {"WhitelistedUserList": 1023456},
                    {"WhitelistedUserList":"AIDA*&903"},
                    {"WhitelistedUserList":"AIDA325ykvo"},
                    {"WhitelistedUserList":"(%$@!)"}],
    "invalidSeparators" : [{"WhitelistedUserList":"AIDAJYPPIFB65RVYU7CCW AIDAJYPPIFB65RVYU7AAD"},
                    {"WhitelistedUserList":"AIDAJYPPIFB65RVYU7CCW/AIDAJYPPIFB65RVY9IP62"},
                    {"WhitelistedUserList":"AIDAJYPPIFB65RVYU7CCW,,AIDAJYPPILP90RVYU7WWC"}]
    }

    invalidExpiryParams = [{"NotUsedTimeOutInDays":"-1"},
    {"NotUsedTimeOutInDays":"5.6"},
    {"NotUsedTimeOutInDays":"ABC"},
    {"NotUsedTimeOutInDays":"*&^"}]

    def test_user_whitelist_parameters_incorrect_entry(self):
        for invalidParam in self.invalidUserWhiteListParams['invalidEntry']:
            response = rule.lambda_handler(buildLambdaEvent(ruleParameters=invalidParam), {})
            self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

    def test_user_whitelist_parameters_incorrect_separators(self):
        for invalidParam in self.invalidUserWhiteListParams['invalidSeparators']:
            response = rule.lambda_handler(buildLambdaEvent(ruleParameters=invalidParam), {})
            self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

    def test_NotUsedTimeOutInDays_parameters_incorrect_entry(self):
        for invalidParam in self.invalidExpiryParams:
            response = rule.lambda_handler(buildLambdaEvent(ruleParameters=invalidParam), {})
            print(invalidParam)
            print(response)
            self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

            
class TestConfigurationChangeNotification(unittest.TestCase):
    
    def setUp(self):
        config_client_mock.reset_mock()
        iam_client_mock.reset_mock()
        sts_client_mock()
  
    def test_changetrigger_Compliant_user_whitelisted(self):
        response = rule.lambda_handler(buildLambdaEvent(parameter_catalog(whitelist='AIDAJYPPIFB65RV8YYLDU'), scheduled=False), {})
        resp_expected = [build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_changetrigger_Compliant_user_whitelisted_60day(self):
        response = rule.lambda_handler(buildLambdaEvent(parameter_catalog(whitelist='AIDAJYPPIFB65RV8YYLDU',expiry=60), scheduled=False), {})
        resp_expected = [build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)
    
    get_user_pwd_compliant = {'User': {'PasswordLastUsed': constructDateTime()}}
    
    def test_changetrigger_Compliant_password_used(self):
        iam_client_mock.get_user = MagicMock(return_value=self.get_user_pwd_compliant)
        response = rule.lambda_handler(buildLambdaEvent(scheduled=False), {})
        resp_expected = [build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)

    list_some_access_keys = {'AccessKeyMetadata':[{'AccessKeyId':'access_key_1'},{'AccessKeyId':'access_key_2'}]}
    
    def test_changetrigger_Compliant_accesskey_used(self):
        iam_client_mock.get_user = MagicMock(return_value=get_user_pwd_days(93))
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(return_value=get_user_access_key_day(87))
        response = rule.lambda_handler(buildLambdaEvent(scheduled=False), {})
        print(response)
        resp_expected = [build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_changetrigger_nonCompliant_no_usage(self):
        iam_client_mock.get_user = MagicMock(return_value=get_user_pwd_days(93))
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(return_value=get_user_access_key_day(93))
        response = rule.lambda_handler(buildLambdaEvent(scheduled=False), {})
        resp_expected = [build_expected_response('NON_COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_changetrigger_nonCompliant_no_usage_with_whitelist(self):
        iam_client_mock.get_user = MagicMock(return_value=get_user_pwd_days(93))
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(return_value=get_user_access_key_day(93))
        response = rule.lambda_handler(buildLambdaEvent(ruleParameters=parameter_catalog(whitelist='AIDAABCD12345ABCDE123'),scheduled=False), {})
        resp_expected = [build_expected_response('NON_COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)

    def test_changetrigger_nonCompliant_no_usage_60days(self):
        iam_client_mock.get_user = MagicMock(return_value=get_user_pwd_days(61))
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(return_value=get_user_access_key_day(61))
        response = rule.lambda_handler(buildLambdaEvent(ruleParameters=parameter_catalog(expiry=60),scheduled=False), {})
        resp_expected = [build_expected_response('NON_COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_changetrigger_Compliant_pwd_used_60days(self):
        iam_client_mock.get_user = MagicMock(return_value=get_user_pwd_days(59))
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(return_value=get_user_access_key_day(61))
        response = rule.lambda_handler(buildLambdaEvent(ruleParameters=parameter_catalog(expiry=60),scheduled=False), {})
        resp_expected = [build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_changetrigger_Compliant_accesskey_used_60days(self):
        iam_client_mock.get_user = MagicMock(return_value=get_user_pwd_days(61))
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(return_value=get_user_access_key_day(59))
        response = rule.lambda_handler(buildLambdaEvent(ruleParameters=parameter_catalog(expiry=60),scheduled=False), {})
        resp_expected = [build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU')]
        assert_successful_evaluation(self, response, resp_expected)

class TestScheduledNotification(unittest.TestCase):

    users_list = { 'Users': [
        { 'UserId': 'AIDAABCD12345ABCDE123',
          'UserName': 'some-user-1',
          'CreateDate': datetime.datetime(2015, 1, 1, tzinfo=tzutc())}, 
        { 'UserId': 'AIDAJYPPIFB65RV8YYLDU',
          'UserName': 'some-user-2',
          'CreateDate': datetime.datetime(2015, 1, 1, tzinfo=tzutc())}, 
        { 'UserId': 'AIDA12345ABCDE12345AB',
          'UserName': 'some-user-3',
          'CreateDate': datetime.datetime(2015, 1, 1, tzinfo=tzutc())}]}
    
    def test_scheduled_Compliant_2_users_whitelisted(self):
        iam_client_mock.list_users = MagicMock(return_value=self.users_list)
        response = rule.lambda_handler(buildLambdaEvent(parameter_catalog(whitelist='AIDAABCD12345ABCDE123, AIDAJYPPIFB65RV8YYLDU'), scheduled=True), {})
        resp_expected = [
            build_expected_response('COMPLIANT', 'AIDAABCD12345ABCDE123'),
            build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU'),
            build_expected_response('NON_COMPLIANT', 'AIDA12345ABCDE12345AB')]
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=3)

    list_one_access_key = {'AccessKeyMetadata':[{'AccessKeyId':'access_key_1'}]}
    list_some_access_keys = {'AccessKeyMetadata':[{'AccessKeyId':'access_key_1'},{'AccessKeyId':'access_key_2'}]}

    def test_scheduled_nonCompliant_user(self):
        iam_client_mock.list_users = MagicMock(return_value=self.users_list)
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_one_access_key)
        iam_client_mock.get_access_key_last_used = MagicMock(side_effect=[get_user_access_key_day(93),get_user_access_key_day(93),get_user_access_key_day(93)])
        response = rule.lambda_handler(buildLambdaEvent(scheduled=True), {})
        resp_expected = [
            build_expected_response('NON_COMPLIANT', 'AIDAABCD12345ABCDE123'),
            build_expected_response('NON_COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU'),
            build_expected_response('NON_COMPLIANT', 'AIDA12345ABCDE12345AB')]
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=3)

    def test_scheduled_Compliant_pwd_Compliant_access_key(self):
        iam_client_mock.list_users = MagicMock(return_value=self.users_list)
        iam_client_mock.list_access_keys = MagicMock(return_value=self.list_some_access_keys)
        iam_client_mock.get_access_key_last_used = MagicMock(side_effect=[get_user_access_key_day(93), get_user_access_key_day(87), get_user_access_key_day(93), get_user_access_key_day(87), get_user_access_key_day(93), get_user_access_key_day(93)])
        response = rule.lambda_handler(buildLambdaEvent(scheduled=True), {})
        resp_expected = [
            build_expected_response('COMPLIANT', 'AIDAABCD12345ABCDE123'),
            build_expected_response('COMPLIANT', 'AIDAJYPPIFB65RV8YYLDU'),
            build_expected_response('NON_COMPLIANT', 'AIDA12345ABCDE12345AB')]
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=3)

    users_list_empty = { 'Users': []}

    def test_scheduled_notApplicable_no_user(self):
        iam_client_mock.list_users = MagicMock(return_value=self.users_list_empty)
        response = rule.lambda_handler(buildLambdaEvent(scheduled=True), {})
        resp_expected = [
            build_expected_response('NOT_APPLICABLE', 'account-id', ComplianceResourceType='AWS::::Account')]
        print(resp_expected)
        assert_successful_evaluation(self, response, resp_expected, ressourcetype='AWS::::Account') 

def assert_successful_evaluation(testClass, response, resp_expected, ressourcetype='AWS::IAM::User', evaluations_count=1):
    testClass.assertEquals(evaluations_count, len(response))
    for r, value in enumerate(response):
        testClass.assertEquals(resp_expected[r]['ComplianceType'], response[r]['ComplianceType'])
        testClass.assertEquals(ressourcetype, response[r]['ComplianceResourceType'])
        testClass.assertEquals(resp_expected[r]['ComplianceResourceId'], response[r]['ComplianceResourceId'])
        testClass.assertTrue(response[r]['OrderingTimestamp'])
        if 'Annotation' in resp_expected[r] or 'Annotation' in response[r]:
            testClass.assertEquals(resp_expected[r]['Annotation'], response[r]['Annotation'])
