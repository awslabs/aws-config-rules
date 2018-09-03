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
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::RestApi'

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
apigw_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name =='apigateway':
            return apigw_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('API_GW_RESTRICTED_IP')

class TestsOnParameter(unittest.TestCase):

    def test_user_whitelist_parameters_not_defined(self):
        invalid_param_not_defined = ['{}',
                                   '{"SomethingElse":"1234578910"}']
        for invalid_entry in invalid_param_not_defined:
            response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_entry), {})
            self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')
            self.assertEqual(response['customerErrorMessage'], 'The parameter with "WhitelistedIPs" as key must be defined.')

    def test_user_whitelist_parameters_no_value(self):
        invalid_param_no_value = '{"WhitelistedIPs": ""}'
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_param_no_value), {})
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')
        self.assertEqual(response['customerErrorMessage'], 'The parameter "WhitelistedIPs" must have a defined value.')

    def test_user_whitelist_parameters_not_string(self):
        invalid_param_not_string = ['{"WhitelistedIPs": {"test":"test2"}}',
                                   '{"WhitelistedIPs": 1023456}']
        for invalid_entry in invalid_param_not_string:
            response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_entry), {})
            self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')
            self.assertEqual(response['customerErrorMessage'], 'The parameter "WhitelistedIPs" must be a string or a list of strings separated by comma.')

    def test_user_whitelist_parameters_not_valid(self):
        invalid_param_not_valid = ['{"WhitelistedIPs":"1234578910"}',
                                   '{"WhitelistedIPs": "10.1.1.1/92"}',
                                   '{"WhitelistedIPs":"10.1.1.1 10.1.1.2"}',
                                   '{"WhitelistedIPs":"10.1.1.1/10.1.1.2"}']
        for invalid_entry in invalid_param_not_valid:
            response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_entry), {})
            self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')
            value = json.loads(invalid_entry)['WhitelistedIPs']
            self.assertEqual(response['customerErrorMessage'], 'The value in parameter "WhitelistedIPs" [' + str(value) + '] is not a valid IP or a valid IP network.')
    
    def test_user_whitelist_parameters_double_comma(self):
        invalid_param_double_comma = '{"WhitelistedIPs":"10.1.1.1,,10.1.1.2"}'
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_param_double_comma), {})
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')
        self.assertEqual(response['customerErrorMessage'], 'The value in parameter "WhitelistedIPs" [] is not a valid IP or a valid IP network.')

class TestsOnCompliance(unittest.TestCase):

    valid_whitelist_ip_single = '{"WhitelistedIPs":"10.1.1.1"}'
    
    valid_whitelist_ip_network = '{"WhitelistedIPs":"10.1.1.1/24"}'
    
    get_rest_with_api_private = {
        'items': [{'name': 'name-api-1', 'endpointConfiguration': {'types': ['PRIVATE']}},
                  {'name': 'name-api-2', 'endpointConfiguration': {'types': ['PRIVATE']}}]
    }
    
    get_rest_with_apis_no_policy = {
        'items': [{'name': 'name-api-1', 'endpointConfiguration': {'types': ['EDGE']}},
                  {'name': 'name-api-2', 'endpointConfiguration': {'types': ['REGIONAL']}},
                  {'name': 'name-api-3', 'endpointConfiguration': {'types': ['PRIVATE']}}]
    }
    
    get_rest_with_apis_policy_no_allow_no_condition_no_ipadress = {
        'items': [{'name': 'name-api-1-no-allow',
                   'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Deny\\\",\\\"Principal\\\":{\\\"AWS\\\":\\\"arn:aws:iam::112233445566:user\\/batman\\\"},\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\\"},{\\\"Effect\\\":\\\"Deny\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.24.34.0\\/23\\\",\\\"10.24.34.0\\/24\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}},
                    {'name': 'name-api-2-no-condition',
                    'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":{\\\"AWS\\\":\\\"arn:aws:iam::112233445566:user\\/batman\\\"},\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\\"},{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\\"}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}},
                   {'name': 'name-api-3-no-ipaddress',
                    'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"NotIpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.24.34.0\\/23\\\",\\\"10.24.34.0\\/24\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}}
                   ]
    }

    def test_no_gw(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value={"items":[]})
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip_single), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_only_private(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_with_api_private)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip_single), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'name-api-1'))
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'name-api-2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_no_policy(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_with_apis_no_policy)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip_single), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'name-api-1', annotation='No resource policy is attached.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'name-api-2', annotation='No resource policy is attached.'))
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'name-api-3'))
        assert_successful_evaluation(self, response, resp_expected, 3)
    
    def test_no_allow_no_condition_no_ipadress(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_with_apis_policy_no_allow_no_condition_no_ipadress)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip_single), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'name-api-1-no-allow'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'name-api-2-no-condition', annotation='The attached policy allows more than the whitelist.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'name-api-3-no-ipaddress', annotation='The attached policy allows more than the whitelist.'))
        assert_successful_evaluation(self, response, resp_expected, 3)

    valid_whitelist_ip = '{"WhitelistedIPs":"10.1.1.1,10.1.2.0/24"}'
    
    get_rest_with_apis_policy_match_whitelist = {
        'items': [{'name': 'name-api-1-match-whitelist-address',
                   'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.1.1.1\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}},
                    {'name': 'name-api-2-match-whitelist-network',
                    'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.1.2.0\\/24\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}}
                   ]
    }
    def test_whitelist_condition_matches(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_with_apis_policy_match_whitelist)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'name-api-1-match-whitelist-address'))
        resp_expected.append(build_expected_response('COMPLIANT', 'name-api-2-match-whitelist-network'))
        assert_successful_evaluation(self, response, resp_expected, 2)
    
    valid_whitelist_ip_more = '{"WhitelistedIPs":"10.1.1.0/24,10.1.2.0/28"}'
    
    get_rest_with_apis_policy_dont_match_whitelist_compliant = {
        'items': [{'name': 'name-api-1-no-match-address',
                   'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.1.1.10\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}},
                    {'name': 'name-api-2-no-match-network',
                    'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.1.2.4\\/30\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}}
                   ]
    }
    def test_COMPLIANT_whitelist_condition_dont_match(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_with_apis_policy_dont_match_whitelist_compliant)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip_more), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'name-api-1-no-match-address'))
        resp_expected.append(build_expected_response('COMPLIANT', 'name-api-2-no-match-network'))
        assert_successful_evaluation(self, response, resp_expected, 2)
    
    get_rest_with_apis_policy_dont_match_whitelist_non_compliant = {
        'items': [{'name': 'name-api-1-no-match-address',
                   'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":\\\"10.1.3.2\\\"}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}},
                    {'name': 'name-api-2-no-match-network',
                    'policy': '{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-east-1:112233445566:4fzg4h5rf2\\/*\\\",\\\"Condition\\\":{\\\"IpAddress\\\":{\\\"aws:SourceIp\\\":[\\\"10.1.1.2\\\",\\\"10.1.3.2\\\","10.1.2.0\\/27\\\"]}}}]}', 
                   'endpointConfiguration': {'types': ['EDGE']}}
                   ]
    }
    def test_NON_COMPLIANT_whitelist_condition_dont_match(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.get_rest_with_apis_policy_dont_match_whitelist_non_compliant)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.valid_whitelist_ip_more), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'name-api-1-no-match-address', annotation='The attached policy allows more than the whitelist.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'name-api-2-no-match-network', annotation='The attached policy allows more than the whitelist.'))
        assert_successful_evaluation(self, response, resp_expected, 2)
    
    

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': True,
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
        'eventLeftScope': True,
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
