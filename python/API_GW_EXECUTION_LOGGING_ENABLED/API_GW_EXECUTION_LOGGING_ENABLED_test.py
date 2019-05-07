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
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::RestApi'

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

RULE = __import__('API_GW_EXECUTION_LOGGING_ENABLED')

class ParameterTest(unittest.TestCase):

    stage_settings_1 = {
        'methodSettings':{
            '*/*':{
                'loggingLevel':'OFF'
            }
        }
    }
    stage_settings_2 = {
        'methodSettings':{
            '*/*':{
                'loggingLevel':'INFO'
            }
        }
    }

    #Scenario 1: Rule Parameter is invalid
    def test_invalid_param_value(self):
        rule_parameters = '{"loggingLevel": "INVALID"}'
        invoking_event = build_invoking_event(self.stage_settings_1, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_parameter_values2(self):
        rule_parameters = '{"loggingLevel": "ERROR,NOTSET"}'
        invoking_event = build_invoking_event(self.stage_settings_1, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    #Scenario 2: Non Compliant
    def test_no_parameter_non_compliant(self):
        rule_parameters = '{}'
        invoking_event = build_invoking_event(self.stage_settings_1, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage', 'Logging Level does not match the value for rule parameter (loggingLevel): [\'ERROR\', \'INFO\'] in this Amazon API Gateway Stage for the following method(s): [*/*].'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3: Compliant
    def test_no_parameter_compliant(self):
        rule_parameters = '{}'
        invoking_event = build_invoking_event(self.stage_settings_2, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

class LoggingLevelTest(unittest.TestCase):
    rule_parameters = '{"loggingLevel": "ERROR,INFO"}'

    #Scenario 2: Non compliant for Resource Type AWS::ApiGateway::Stage
    def test_logging_level_default_off(self):
        stage_settings = {
            'methodSettings':{}
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit', 'AWS::ApiGateway::Stage', 'Logging is not configured for this Amazon API Gateway Stage.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_overriden_off(self):
        stage_settings = {
            'methodSettings':{
                '~1test~1{proxy}/GET':{
                    'loggingLevel':'OFF'
                },
                '*/*':{
                    'loggingLevel':'INFO'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit', 'AWS::ApiGateway::Stage', 'Logging Level does not match the value for rule parameter (loggingLevel): [\'ERROR\', \'INFO\'] in this Amazon API Gateway Stage for the following method(s): [~1test~1{proxy}/GET].'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_info_non_compliant(self):
        stage_settings = {
            'methodSettings':{
                '*/*':{
                    'loggingLevel':'INFO'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        rule_parameters = '{"loggingLevel": "ERROR"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage', 'Logging Level does not match the value for rule parameter (loggingLevel): [\'ERROR\'] in this Amazon API Gateway Stage for the following method(s): [*/*].'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_error_non_compliant(self):
        stage_settings = {
            'methodSettings':{
                '*/*':{
                    'loggingLevel':'ERROR'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        rule_parameters = '{"loggingLevel": "INFO"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage', 'Logging Level does not match the value for rule parameter (loggingLevel): [\'INFO\'] in this Amazon API Gateway Stage for the following method(s): [*/*].'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3: Compliant for Resource Type AWS::ApiGateway::Stage
    def test_logging_level_info(self):
        stage_settings = {
            'methodSettings':{
                '*/*':{
                    'loggingLevel':'INFO'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_error(self):
        stage_settings = {
            'methodSettings':{
                '*/*':{
                    'loggingLevel':'ERROR'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_info_compliant(self):
        stage_settings = {
            'methodSettings':{
                '~1test~1{proxy}/GET':{
                    'loggingLevel':'INFO'
                },
                '*/*':{
                    'loggingLevel':'INFO'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        rule_parameters = '{"loggingLevel": "INFO"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_error_compliant(self):
        stage_settings = {
            'methodSettings':{
                '*/*':{
                    'loggingLevel':'ERROR'
                }
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGateway::Stage', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test')
        rule_parameters = '{"loggingLevel": "ERROR"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 2: Non Compliant for Resource Type AWS::ApiGatewayV2::Stage
    def test_apiv2_change_loglevel_to_off(self):
        stage_settings = {
            'defaultRouteSettings':{
                'loggingLevel':'OFF'
            },
        }
        RULE.ASSUME_ROLE_MODE = False
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGatewayV2::Stage', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test')
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'AWS::ApiGatewayV2::Stage', 'Logging Level does not match the value for rule parameter (loggingLevel): [\'ERROR\', \'INFO\'] in this Amazon API Gateway Stage.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3: Compliant for Resource Type AWS::ApiGatewayV2::Stage
    def test_apiv2_change_loglevel_to_info(self):
        stage_settings = {
            'defaultRouteSettings':{
                'loggingLevel':'INFO'
            }
        }
        invoking_event = build_invoking_event(stage_settings, 'AWS::ApiGatewayV2::Stage', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test')
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'AWS::ApiGatewayV2::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################

def build_invoking_event(stage_settings, resource_type, resource_id):
    invoking_event_to_return = {
        'configurationItem':{
            'configuration':stage_settings,
            'configurationItemStatus':'OK',
            'configurationItemCaptureTime':'2019-04-13T17:18:21.693Z',
            'resourceType':resource_type,
            'resourceId':resource_id,
            'resourceName':'test',
            'ARN':resource_id
            },
        'messageType':'ConfigurationItemChangeNotification'
        }
    return json.dumps(invoking_event_to_return)

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
