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

config_client_mock = MagicMock()
lambda_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        if client_name == 'lambda':
            return lambda_client_mock
        if client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('LAMBDA_CODE_IS_VERSIONED')

class TestOnLambdaCodeIsVersioned(unittest.TestCase):
    functionListWithFunctions = {
      "Functions": [{
          "FunctionName": "lambda-code-is-versioned"
       }]}
    functionListWithoutFunctions = {"Functions": []}


    versionListWithVersioning = { 
      "Versions": [
        {"Version": "$LATEST"}, 
        {"Version": "1"}, 
        {"Version": "2"}, 
        {"Version": "3"}
      ]
    }
    versionListWithoutVersioning = { 
      "Versions": [{"Version": "$LATEST"}]}

    functionWithAliasNotPointingToLatest = {
      "Aliases": [
        {"FunctionVersion": "3"}, 
        {"FunctionVersion": "1"}, 
        {"FunctionVersion": "1"}, 
        {"FunctionVersion": "3"}
      ]
    }
    functionWithAliasAndPointingToLatest = {
      "Aliases": [
        {"FunctionVersion": "3"}, 
        {"FunctionVersion": "1"}, 
        {"FunctionVersion": "$LATEST"}, 
        {"FunctionVersion": "3"}
      ]
    }
    functionWithoutAlias = {"Aliases": []}

    complianceEvaluationResult = {
      "EvaluationResults": [
        {
          "EvaluationResultIdentifier": {
            "EvaluationResultQualifier": {
              "ResourceId": "rdkLambdaVersion", 
            }
          }, 
        }, 
      ], 
    }
    complianceEvaluationWithEmptyResult = {
      "EvaluationResults": []
      }

    def setUp(self):
        pass

    def test_no_lambda_function_present(self):
        lambda_client_mock.list_functions = MagicMock(return_value = self.functionListWithoutFunctions)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value = self.complianceEvaluationWithEmptyResult)
        response = rule.lambda_handler(build_lambda_event(),{})
        resp_expected = []
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::::Account',
            'ComplianceResourceId' : '123456789012',
            'ComplianceType': "NOT_APPLICABLE"
        })
        assert_successful_evaluation(self,response, resp_expected)

    def test_no_versioning_for_lambda_function(self):
        lambda_client_mock.list_functions = MagicMock(return_value = self.functionListWithFunctions)
        lambda_client_mock.list_versions_by_function = MagicMock(return_value = self.versionListWithoutVersioning)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value = self.complianceEvaluationWithEmptyResult)
        response = rule.lambda_handler(build_lambda_event(),{})
        resp_expected = []
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::Lambda::Function',
            'ComplianceResourceId' : 'lambda-code-is-versioned',
            'ComplianceType': "NON_COMPLIANT"
        })
        assert_successful_evaluation(self,response, resp_expected)

    def test_no_alias_present_for_lambda_function(self):
        lambda_client_mock.list_functions = MagicMock(return_value = self.functionListWithFunctions)
        lambda_client_mock.list_versions_by_function = MagicMock(return_value = self.versionListWithVersioning)
        lambda_client_mock.list_aliases = MagicMock(return_value = self.functionWithoutAlias)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value = self.complianceEvaluationWithEmptyResult)
        response = rule.lambda_handler(build_lambda_event(),{})
        resp_expected = []
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::Lambda::Function',
            'ComplianceResourceId' : 'lambda-code-is-versioned',
            'ComplianceType': "NON_COMPLIANT"})
        assert_successful_evaluation(self,response, resp_expected)

    def test_alias_pointing_to_latest_version(self):
        lambda_client_mock.list_functions = MagicMock(return_value = self.functionListWithFunctions)
        lambda_client_mock.list_versions_by_function = MagicMock(return_value = self.versionListWithVersioning)
        lambda_client_mock.list_aliases = MagicMock(return_value = self.functionWithAliasAndPointingToLatest)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value = self.complianceEvaluationWithEmptyResult)
        response = rule.lambda_handler(build_lambda_event(),{})
        resp_expected = []
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::Lambda::Function',
            'ComplianceResourceId' : 'lambda-code-is-versioned',
            'ComplianceType': "NON_COMPLIANT"
        })
        assert_successful_evaluation(self,response, resp_expected)

    def test_alias_pointing_not_pointing_to_latest(self):
        lambda_client_mock.list_functions = MagicMock(return_value = self.functionListWithFunctions)
        lambda_client_mock.list_versions_by_function = MagicMock(return_value = self.versionListWithVersioning)
        lambda_client_mock.list_aliases = MagicMock(return_value = self.functionWithAliasNotPointingToLatest)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value = self.complianceEvaluationWithEmptyResult)
        response = rule.lambda_handler(build_lambda_event(),{})
        resp_expected = []
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::Lambda::Function',
            'ComplianceResourceId' : 'lambda-code-is-versioned',
            'ComplianceType': "COMPLIANT"
        })
        assert_successful_evaluation(self,response, resp_expected)

    def test_NOT_APPLICABLE_for_deleted_lambda_function(self):
        lambda_client_mock.list_functions = MagicMock(return_value = self.functionListWithFunctions)
        lambda_client_mock.list_versions_by_function = MagicMock(return_value = self.versionListWithVersioning)
        lambda_client_mock.list_aliases = MagicMock(return_value = self.functionWithAliasNotPointingToLatest)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value = self.complianceEvaluationResult)
        response = rule.lambda_handler(build_lambda_event(),{})
        resp_expected = []
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::Lambda::Function',
            'ComplianceResourceId' : 'rdkLambdaVersion',
            'ComplianceType': "NOT_APPLICABLE"
        })
        resp_expected.append({
            'ComplianceResourceType' : 'AWS::Lambda::Function',
            'ComplianceResourceId' : 'lambda-code-is-versioned',
            'ComplianceType': "COMPLIANT"
        })
        assert_successful_evaluation(self, response, resp_expected, 2)

def build_lambda_event():
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    return {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': True,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
} 

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if "Annotation" in resp_expected:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for r in range(len(resp_expected)):
            testClass.assertEquals(resp_expected[r]['ComplianceType'], response[r]['ComplianceType'])
            testClass.assertEquals(resp_expected[r]['ComplianceResourceType'], response[r]['ComplianceResourceType'])
            testClass.assertEquals(resp_expected[r]['ComplianceResourceId'], response[r]['ComplianceResourceId'])
            testClass.assertTrue(response[r]['OrderingTimestamp'])
            if "Annotation" in resp_expected[r]:
                testClass.assertEquals(resp_expected[r]['Annotation'], response[r]['Annotation'])
