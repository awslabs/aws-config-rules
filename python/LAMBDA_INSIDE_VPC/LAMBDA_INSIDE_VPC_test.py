import sys
import json
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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

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

RULE = __import__('LAMBDA_INSIDE_VPC')

class ComplianceTestScenarios(unittest.TestCase):

    rule_empty_parameter_value = '{"subnetId":""}'
    rule_invalid_parameter = '{"subnetId":"vpc-123456789, sub-123123123"}'
    rule_valid_parameter = '{"subnetId":"subnet-123456789, subnet-123123123"}'

    lambda_inside_vpc = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
        "vpcConfig": {
            "subnetIds": [
                "subnet-123123123",
                "subnet-123456789"
            ],
            "securityGroupIds": [
                "sg-f236a088"
            ]
        }
    }

    lambda_outside_vpc = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:234759432549:function:test_function",
    }

    lambda_outside_vpc_scenario_2 = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
        "vpcConfig": {
            "subnetIds": [
            ],
            "securityGroupIds": [
            ]
        }
    }

    lambda_different_subnet = {
        "functionName": "test_function",
        "functionArn": "arn:aws:lambda:us-west-2:123456789012:function:test_function",
        "vpcConfig": {
            "subnetIds": [
                "subnet-000000000",
                "subnet-123456789"
            ],
            "securityGroupIds": [
                "sg-f236a088"
            ]
        }
    }


    # common scenarios
    def test_invalid_parameter_value(self):
        invoking_event = generate_invoking_event(self.lambda_inside_vpc)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_invalid_parameter), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'Invalid value for the parameter "subnetId", Expected Comma-separated list of Subnet ID\'s that Lambda functions must belong to.')

    # Scenario 2
    def test_empty_parameter_value(self):
        invoking_event = generate_invoking_event(self.lambda_inside_vpc)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_empty_parameter_value), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test_function', 'AWS::Lambda::Function'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 3.a
    def test_lambda_outside_vpc(self):
        invoking_event = generate_invoking_event(self.lambda_outside_vpc)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test_function', 'AWS::Lambda::Function', 'This Lambda Function is not in VPC.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 3.b
    def test_lambda_outside_vpc_2(self):
        invoking_event = generate_invoking_event(self.lambda_outside_vpc_scenario_2)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test_function', 'AWS::Lambda::Function', 'This Lambda Function is not in VPC.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4
    def test_non_matching_subnet(self):
        invoking_event = generate_invoking_event(self.lambda_different_subnet)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test_function', 'AWS::Lambda::Function', 'This Lambda Function is not associated with the subnets specified in the "subnetId" input parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5
    def test_matching_subnet(self):
        invoking_event = generate_invoking_event(self.lambda_inside_vpc)
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters=self.rule_valid_parameter), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test_function', 'AWS::Lambda::Function'))
        assert_successful_evaluation(self, response, resp_expected)


####################
# Helper Functions #
####################

def generate_invoking_event(test_configuration):
    invoking_event = '{"configurationItem":{"configuration":' \
    + json.dumps(test_configuration) \
    + ',"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::Lambda::Function","resourceId":"test_function"},"messageType":"ConfigurationItemChangeNotification"}'

    return invoking_event

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
