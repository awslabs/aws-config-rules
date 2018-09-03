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
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

CONFIG_CLIENT_MOCK = MagicMock()
IAM_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'iam':
            return IAM_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('LAMBDA_ROLE_ALLOWED_ON_LOGGING')

def assert_successful_evaluation(testClass, response, resp_expected):
    testClass.assertEquals(response[0]['ComplianceType'], resp_expected)

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

def build_invoking_event(item_status='OK'):
    invoking_event = {
        "configurationItemDiff":"SomeDifference",
        "notificationCreationTime":"SomeTime",
        "messageType":"SomeType",
        "recordVersion":"SomeVersion",
        "configurationItem":
        {   
            "relationships":[{"resourceName":"some_role"}],
            "configurationItemCaptureTime": "2018-05-11T17:53:48.872Z",
            "configurationItemStatus": item_status,
            "configurationStateId": "1526061228872",
            "arn": "arn:aws:lambda:us-east-1:823362693882:function:test-function",
            "resourceType": "AWS::Lambda::Function",
            "resourceId": "test-function",
            "resourceName": "test-function",
            "configuration": {
                "functionName": "test-function",
                "functionArn": "arn:aws:lambda:us-east-1:823362693882:function:test-function",
                "role": "some-role-arn"
            }
        }
    }
    return json.dumps(invoking_event)

def build_lambda_event(ruleParameters='{}', invokingEvent=build_invoking_event()):
    return({
        "invokingEvent" : invokingEvent,
        "ruleParameters" : ruleParameters,
        "resultToken" : "TESTMODE",
        "eventLeftScope" : False,
        "executionRoleArn" : "arn:aws:iam::123456789012:role/service-role/config-role",
        "configRuleArn" : "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan",
        "configRuleName" : "LAMBDA_ROLE_ALLOWED_ON_LOGGING",
        "configRuleId" : "config-rule-8fngan",
        "accountId" : "SampleID"
        })

def gen_statement(action="*", resource="*", effect="Allow"):
    return {
        "Action": action,
        "Resource": resource,
        "Effect": effect
    }
    
def gen_statement_list(statement=gen_statement(), statement2=False, statement3=False):
    statement_list = []
    statement_list.append(statement)
    if statement2:
        statement_list.append(statement2)
    if statement3:
        statement_list.append(statement3)
    return statement_list

def gen_policy_api(type="inline", statement_list=gen_statement_list()):
    if type == "inline":
        return {
        "RoleName": "AdminLambda",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": statement_list
            }
        }
    if type == "list_attached":
        return {
            "AttachedPolicies": [
                {
                    "PolicyName": "some-policy-name",
                    "PolicyArn": "some-policy-arn"
                    }
                ]
            }
    if type == "get_policy": 
        return {
            "Policy": {
                "PolicyName": "some-policy-name",
                "Arn": "some-policy-arn",
                "DefaultVersionId": "some-version-id" 
                }
            }
    if type == "get_policy_version":
        return {
            "PolicyVersion": {
                "Document": {
                    "Statement": statement_list
                }
            }
        }

class TestScenario1DeletedRole(unittest.TestCase):
    def test_NOT_APPLICABLE_lambda_function_deleted(self):
        invokEvent = build_invoking_event("ResourceDeleted")
        lambdaEvent = build_lambda_event(invokingEvent=invokEvent)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NOT_APPLICABLE"
        assert_successful_evaluation(self, response, resp_expected)

class TestScenario2AWSManagedRole(unittest.TestCase):
    def test_COMPLIANT_AWSLambdaBasicExecution_attached_on_role(self):
        list_attached_role_pl = {
            "AttachedPolicies": [
                {
                    "PolicyName": "AWSLambdaBasicExecutionRole-11389b43-d62e-4847-a0af-a967a8e02578",
                    "PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    }
                ]
            }
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

class TestScenario3NoPolicyOnRole(unittest.TestCase):
    def test_NON_COMPLIANT_no_policy_attached_on_role_case(self):
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)
  
class TestScenario4ActionStar(unittest.TestCase):

    def test_COMPLIANT_action_star_allow_string_inline(self):
        get_pl = gen_policy_api()
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_COMPLIANT_action_star_allow_list_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(action=["some-action","*"])))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)
        
    def test_NON_COMPLIANT_action_star_deny_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(effect="Deny")))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_NON_COMPLIANT_action_star_other_resource_string_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(resource="something_else")))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_COMPLIANT_action_star_resource_list_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(resource=["something_else","*"])))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)
        
    def test_COMPLIANT_action_star_allow_managed(self):
        list_attached_role_pl = gen_policy_api(type="list_attached")
        get_pl = gen_policy_api(type="get_policy")
        get_pl_version = gen_policy_api(type="get_policy_version")

        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_NON_COMPLIANT_action_star_deny_managed(self):
        list_attached_role_pl = gen_policy_api(type="list_attached")
        get_pl = gen_policy_api(type="get_policy")
        get_pl_version = gen_policy_api(type="get_policy_version",statement_list=gen_statement_list(gen_statement(effect="Deny")))

        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_COMPLIANT_action_star_resource_ok_managed(self):
        list_attached_role_pl = gen_policy_api(type="list_attached")
        get_pl = gen_policy_api(type="get_policy")
        get_pl_version = gen_policy_api(type="get_policy_version",statement_list=gen_statement_list(gen_statement(resource="arn:aws:logs:*")))

        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

class TestScenario5LogStar(unittest.TestCase):
    
    def test_COMPLIANT_action_logstar_allow_string_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(action="log:*")))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_COMPLIANT_action_logstar_allow_list_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(action=["some-action","log:*"])))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)
        
    def test_NON_COMPLIANT_action_logstar_deny_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(action="log:*",effect="Deny")))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_NON_COMPLIANT_action_logstar_other_resource_string_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(action="log:*", resource="something_else")))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_COMPLIANT_action_logstar_resource_list_inline(self):
        get_pl = gen_policy_api(statement_list=gen_statement_list(gen_statement(action="log:*", resource=["something_else","*"])))
        list_attached_role_pl = {"AttachedPolicies": []}
        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
        IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)
        
    def test_COMPLIANT_action_logstar_allow_managed(self):
        list_attached_role_pl = gen_policy_api(type="list_attached")
        get_pl = gen_policy_api(type="get_policy")
        get_pl_version = gen_policy_api(type="get_policy_version",statement_list=gen_statement_list(gen_statement(action="log:*")))

        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_NON_COMPLIANT_action_logstar_deny_managed(self):
        list_attached_role_pl = gen_policy_api(type="list_attached")
        get_pl = gen_policy_api(type="get_policy")
        get_pl_version = gen_policy_api(type="get_policy_version",statement_list=gen_statement_list(gen_statement(action="log:*",effect="Deny")))

        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "NON_COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)

    def test_COMPLIANT_action_logstar_resource_ok_managed(self):
        list_attached_role_pl = gen_policy_api(type="list_attached")
        get_pl = gen_policy_api(type="get_policy")
        get_pl_version = gen_policy_api(type="get_policy_version",statement_list=gen_statement_list(gen_statement(action="log:*",resource="arn:aws:logs:*")))

        IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
        IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
        IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
        IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

        lambdaEvent = build_lambda_event()
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = "COMPLIANT"
        assert_successful_evaluation(self, response, resp_expected)
    
class TestScenario6LogExactActions(unittest.TestCase):
    CreateLogGroup = gen_statement(action="logs:CreateLogGroup")
    CreateLogStream = gen_statement(action="logs:CreateLogStream")
    PutLogEvents = gen_statement(action="logs:PutLogEvents")
    PutLogEventsDeny = gen_statement(action="logs:PutLogEvents", effect="Deny")
    PutLogEventsBadResource = gen_statement(action="logs:PutLogEvents", resource="some-bad-resource")
    statement_list_all_in_one = gen_statement_list(gen_statement(action=["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"]))
    statement_list_all_in_three = gen_statement_list(CreateLogGroup, CreateLogStream, PutLogEvents)
    statement_list_all_in_three_with_deny = gen_statement_list(CreateLogGroup, CreateLogStream, PutLogEventsDeny)
    statement_list_all_in_three_with_bad_resource = gen_statement_list(CreateLogGroup, CreateLogStream, PutLogEventsBadResource)

    def test_COMPLIANT_action_logexactaction_inline(self):
        for state in [self.statement_list_all_in_one, self.statement_list_all_in_three]:
            get_pl = gen_policy_api(statement_list=state)
            list_attached_role_pl = {"AttachedPolicies": []}
            IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
            IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
            IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
            lambdaEvent = build_lambda_event()
            response = rule.lambda_handler(lambdaEvent, {})
            resp_expected = "COMPLIANT"
            assert_successful_evaluation(self, response, resp_expected)
        
    def test_NON_COMPLIANT_action_logexactaction_inline(self):
        for state in [self.statement_list_all_in_three_with_deny, self.statement_list_all_in_three_with_bad_resource]:
            get_pl = gen_policy_api(statement_list=state)
            list_attached_role_pl = {"AttachedPolicies": []}
            IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
            IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": ["some-inline-name-policy"]})
            IAM_CLIENT_MOCK.get_role_policy = MagicMock(return_value=get_pl)
            lambdaEvent = build_lambda_event()
            response = rule.lambda_handler(lambdaEvent, {})
            resp_expected = "NON_COMPLIANT"
            assert_successful_evaluation(self, response, resp_expected)
        
    def test_COMPLIANT_action_logexactaction_managed(self):
        for state in [self.statement_list_all_in_one, self.statement_list_all_in_three]:
            list_attached_role_pl = gen_policy_api(type="list_attached")
            get_pl = gen_policy_api(type="get_policy")
            get_pl_version = gen_policy_api(type="get_policy_version",statement_list=state)

            IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
            IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
            IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
            IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

            lambdaEvent = build_lambda_event()
            response = rule.lambda_handler(lambdaEvent, {})
            resp_expected = "COMPLIANT"
            assert_successful_evaluation(self, response, resp_expected)
        
    def test_NOT_COMPLIANT_action_logexactaction_managed(self):
        for state in [self.statement_list_all_in_three_with_deny, self.statement_list_all_in_three_with_bad_resource]:
            list_attached_role_pl = gen_policy_api(type="list_attached")
            get_pl = gen_policy_api(type="get_policy")
            get_pl_version = gen_policy_api(type="get_policy_version",statement_list=state)

            IAM_CLIENT_MOCK.list_attached_role_policies = MagicMock(return_value=list_attached_role_pl)
            IAM_CLIENT_MOCK.get_policy = MagicMock(return_value=get_pl)
            IAM_CLIENT_MOCK.get_policy_version = MagicMock(return_value=get_pl_version)
            IAM_CLIENT_MOCK.list_role_policies = MagicMock(return_value={"PolicyNames": []})

            lambdaEvent = build_lambda_event()
            response = rule.lambda_handler(lambdaEvent, {})
            resp_expected = "NON_COMPLIANT"
            assert_successful_evaluation(self, response, resp_expected)
