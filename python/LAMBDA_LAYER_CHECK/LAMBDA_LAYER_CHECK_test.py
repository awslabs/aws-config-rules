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
DEFAULT_RESOURCE_TYPE = 'AWS::Lambda::Function'

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

RULE = __import__('LAMBDA_LAYER_CHECK')

class ParametersTest(unittest.TestCase):
    rule_parameter_layer_not_provided = '{"MinLayerVersion" : "1"}'
    rule_parameter_version_not_provided = '{"LayerArn" : "arn:aws:lambda:eu-west-1:123456789012:layer:layername"}'
    rule_parameter_layer_invalid = '{"LayerArn" : "arn:aws:lambda:eu-west-1:42:layer:layername", "MinLayerVersion" : "2"}'
    rule_parameter_version_invalid = '{"LayerArn" : "arn:aws:lambda:eu-west-1:123456789012:layer:layername", "MinLayerVersion" : "0"}'

    simple_function = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function"
    }

    def test_scenario_1_layer_param_not_provided(self):
        invoking_event = generate_invoking_event(self.simple_function)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameter_layer_not_provided), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'LayerArn must be provided')

    def test_scenario_2_version_param_not_provided(self):
        invoking_event = generate_invoking_event(self.simple_function)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameter_version_not_provided), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'MinLayerVersion must be provided')

    def test_scenario_3_layer_invalid(self):
        invoking_event = generate_invoking_event(self.simple_function)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameter_layer_invalid), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'LayerArn must be valid: arn:aws:lambda:{region}:{accountid}:layer:{layername}, without version number')

    def test_scenario_4_version_invalid(self):
        invoking_event = generate_invoking_event(self.simple_function)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameter_version_invalid), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'MinLayerVersion must be a positive integer')

class RuleTest(unittest.TestCase):
    rule_parameters = '{"LayerArn" : "arn:aws:lambda:eu-west-1:123456789012:layer:layername", "MinLayerVersion" : "2"}'

    def test_scenario_5_no_layer_configured(self):
        function_without_layer = {
            "functionName": "test_function",
            "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
            "packageType": "Zip",
            "layers": []
        }
        invoking_event = generate_invoking_event(function_without_layer)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameters), {})

        assert_successful_evaluation(self, response, [build_expected_response('NON_COMPLIANT', '123456789012', annotation='No layer is configured for this Lambda function')])


    def test_scenario_6_layer_not_matching(self):
        function_another_layer = {
            "functionName": "test_function",
            "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
            "packageType": "Zip",
            "layers": [
                {"arn": "arn:aws:lambda:eu-west-1:123456789012:layer:superlayer:5"}
            ]
        }
        invoking_event = generate_invoking_event(function_another_layer)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameters), {})

        assert_successful_evaluation(self, response, [build_expected_response('NON_COMPLIANT', '123456789012', annotation='Layer arn:aws:lambda:eu-west-1:123456789012:layer:layername not used for this Lambda function')])

    def test_scenario_7_wrong_version(self):
        function_old_version = {
            "functionName": "test_function",
            "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
            "packageType": "Zip",
            "layers": [
                {"arn": "arn:aws:lambda:eu-west-1:123456789012:layer:layername:1"}
            ]
        }
        invoking_event = generate_invoking_event(function_old_version)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameters), {})

        assert_successful_evaluation(self, response, [build_expected_response('NON_COMPLIANT', '123456789012', annotation='Wrong layer version (was 1, expected 2+)')])

    def test_scenario_8_everything_ok(self):
        function_ok = {
            "functionName": "test_function",
            "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
            "packageType": "Zip",
            "layers": [
                {"arn": "arn:aws:lambda:eu-west-1:123456789012:layer:layername:3"}
            ]
        }
        invoking_event = generate_invoking_event(function_ok)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameters), {})

        assert_successful_evaluation(self, response, [build_expected_response('COMPLIANT', '123456789012')])

    def test_scenario_9_not_zip_pkg(self):
        function_ok = {
            "functionName": "test_function",
            "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
            "packageType": "Image"
        }
        invoking_event = generate_invoking_event(function_ok)
        response = RULE.lambda_handler(
            build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_parameters), {})

        assert_successful_evaluation(self, response, [build_expected_response('NOT_APPLICABLE', '123456789012', annotation='Layers can only be used with functions using Zip package type')])

####################
# Helper Functions #
####################

def generate_invoking_event(test_configuration):
    invoking_event = '{"configurationItem":{"configuration":' \
                     + json.dumps(test_configuration) \
                     + ',"configurationItemCaptureTime":"2019-04-18T08:17:52.315Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::Lambda::Function","resourceId":"123456789012"},"messageType":"ConfigurationItemChangeNotification"}'
    return invoking_event


def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName': 'myrule',
        'executionRoleArn': 'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken': 'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return


def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE,
                            annotation=None):
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

