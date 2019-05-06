import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import json
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::Stage'

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

RULE = __import__('API_GW_CACHE_ENABLED_AND_ENCRYPTED')

class ComplianceTest(unittest.TestCase):
    cache_not_enabled = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": False,
        "cacheClusterStatus": "NOT_AVAILABLE",
        "methodSettings": {}
    }

    cache_enabled_not_encrypted = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": True,
        "methodSettings": {
            "*/*": {
                "cachingEnabled": True,
                "cacheDataEncrypted": False
            }
        }
    }


    method_cache_not_enabled = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": True,
        "methodSettings": {
            "*/*": {
                "cachingEnabled": True,
                "cacheDataEncrypted": True
            },
            "~1/HEAD": {
                "cachingEnabled": False,
                "cacheDataEncrypted": False
            }
        }
    }

    method_encryption_not_enabled = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": True,
        "methodSettings": {
            "*/*": {
                "cachingEnabled": True,
                "cacheDataEncrypted": True
            },
            "~1/HEAD": {
                "cachingEnabled": True,
                "cacheDataEncrypted": False
            }
        }
    }

    cache_enabled_encrypted = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": True,
        "methodSettings": {
            "*/*": {
                "cachingEnabled": True,
                "cacheDataEncrypted": True
            }
        }
    }

    method_cache_encryption_false = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": True,
        "methodSettings": {
            "*/*": {
                "cachingEnabled": True,
                "cacheDataEncrypted": True
            },
            "~1/HEAD": {
                "cachingEnabled": True,
                "cacheDataEncrypted": False,
            },
            "~1/POST": {
                "cachingEnabled": False,
                "cacheDataEncrypted": False,
            }
        }
    }


    method_cache_enabled_encrypted = {
        "deploymentId": "upwjvm",
        "stageName": "StageV1",
        "cacheClusterEnabled": True,
        "methodSettings": {
            "*/*": {
                "cachingEnabled": True,
                "cacheDataEncrypted": True
            },
            "~1/HEAD": {
                "cachingEnabled": True,
                "cacheDataEncrypted": True,
            }
        }
    }

    # Scenario 1: If caching is not enabled for the stage, return NON_COMPLIANT
    def test_scenario_1_cache_not_enabled(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.cache_not_enabled)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage', 'This Amazon API Gateway Stage is not configured for cache.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 2: If caching is enabled for the stage but not enabled for one or more of the methods, return NON_COMPLIANT
    def test_scenario_2_method_cache_not_enabled(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.method_cache_not_enabled)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage', 'Cache is not configured in this Amazon API Gateway Stage for the following method(s): ~1/HEAD'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 3: If caching is enabled for the stage but not enabled or encrypted for one or more of the methods, return NON_COMPLIANT
    def test_scenario_3_method_cache_encryption_false(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.method_cache_encryption_false)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage', 'The cache is either not configured or not encrypted in this Amazon API Gateway Stage for the following method(s): ~1/POST ~1/HEAD'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4: If caching is enabled but not encrypted for the stage, return NON_COMPLIANT
    def test_scenario_4_cache_enabled_not_encrypted(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.cache_enabled_not_encrypted)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage', 'The cache is not encrypted in this Amazon API Gateway Stage for the following method(s): */*'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4: If caching is enabled for the stage and all methods but not encrypted for one or more of the methods, return NON_COMPLIANT
    def test_scenario_4_method_encryption_not_enabled(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.method_encryption_not_enabled)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage', 'The cache is not encrypted in this Amazon API Gateway Stage for the following method(s): ~1/HEAD'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5: If caching is enabled and encrypted for the stage, return COMPLIANT
    def test_scenario_5_cache_enabled_encrypted(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.cache_enabled_encrypted)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5: If caching is enabled amd encrypted for the stage and all methods, return COMPLIANT
    def test_scenario_5_method_cache_enabled_encrypted(self):
        resp_expected = []
        invoking_event = '{"configurationItem": {"configuration":' + json.dumps(self.method_cache_enabled_encrypted)+ ',"configurationItemCaptureTime": "2019-03-20T04:54:40.620Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1", "resourceName": "dev", "resourceCreationTime": "2018-09-18T16:17:40.430Z"}, "messageType": "ConfigurationItemChangeNotification"}'

        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event), {})
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/1ab2cd34ef/stages/StageV1', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)


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
