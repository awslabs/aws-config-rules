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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
SAGEMAKER_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'sagemaker':
            return SAGEMAKER_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('SAGEMAKER_ENDPOINT_CONFIG_KMS_KEY_CONFIGURED')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'
    
    rule_parameters_scenario3='{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487h3d, arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4edg-8131-7c98e9487e3d"}'
    list_endpoints_scenario3=[{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    describe_endpoint_config_scenario3=[{'EndpointConfigName':'endpoint1','EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'},{'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2'}]

    rule_parameters_scenario4='{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487h3d, arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4edg-8131-7c98e9487e3d"}'
    list_endpoints_scenario4=[{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    describe_endpoint_config_scenario4=[{'EndpointConfigName':'endpoint1','KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d','EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'},{'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2','KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d'}]
    
    rule_parameters_scenario5='{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d, arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3f"}'
    list_endpoints_scenario5=[{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    describe_endpoint_config_scenario5=[{'EndpointConfigName':'endpoint1','KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d','EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'},{'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2','KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3f'}]

    rule_parameters_scenario6 ='{}'
    list_endpoints_scenario6=[{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    describe_endpoint_config_scenario6=[{'EndpointConfigName':'endpoint1','KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d','EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'},{'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2','KmsKeyId': 'arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3f'}]


    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        pass

    def test_sample(self):
        self.assertTrue(True)

    #Scenario 2 No Amazon SageMaker endpoint configs exist
    def test_scenario_2_is_no_enpoints(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": [{'EndpointConfigs': []}]})
        lambda_event = build_lambda_scheduled_event(rule_parameters=None)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3 Given: At least one Amazon SageMaker endpoint config exists
    #And: 'KmsKeyId' is not specified for the Amazon SageMaker Endpoint Config

    def test_scenario_3_is_no_kms_present(self):
        
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario3})
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario3)
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config=MagicMock(side_effect=self.describe_endpoint_config_scenario3)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT','endpoint1',annotation="No AWS KMS Key is configured for this Amazon SageMaker Endpoint Config."))
        resp_expected.append(build_expected_response('NON_COMPLIANT','endpoint2',annotation="No AWS KMS Key is configured for this Amazon SageMaker Endpoint Config."))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_4_no_matching_keyids(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario4})
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario4)
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config=MagicMock(side_effect=self.describe_endpoint_config_scenario4)
        resp_expected = []
        response = rule.lambda_handler(lambda_event, {})
        resp_expected.append(build_expected_response('NON_COMPLIANT','endpoint1',annotation="AWS KMS Key configured for this Amazon SageMaker Endpoint Config is not an KMS Key allowed in the rule parameter (keyIds)"))
        resp_expected.append(build_expected_response('NON_COMPLIANT','endpoint2',annotation="AWS KMS Key configured for this Amazon SageMaker Endpoint Config is not an KMS Key allowed in the rule parameter (keyIds)"))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_5_compliant(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario5})
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config=MagicMock(side_effect=self.describe_endpoint_config_scenario5)
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario5)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT','endpoint1'))
        resp_expected.append(build_expected_response('COMPLIANT','endpoint2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_6_compliant(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario6})
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config=MagicMock(side_effect=self.describe_endpoint_config_scenario6)
        
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario6)
        resp_expected = []
        response = rule.lambda_handler(lambda_event, {})
        resp_expected.append(build_expected_response('COMPLIANT','endpoint1'))
        resp_expected.append(build_expected_response('COMPLIANT','endpoint2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

class ParmetersTest(unittest.TestCase):
    list_endpoints_scenario1=[{'EndpointConfigs':[{'EndpointConfigName':'endpoint1'}, {'EndpointConfigName':'endpoint2'}]}]
    describe_endpoint_config_scenario1=[{'EndpointConfigName':'endpoint1','EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint1'},{'EndpointConfigName': 'endpoint2', 'EndpointConfigArn': 'arn:aws:sagemaker:us-east-1:305333956852:endpoint-config/endpoint2'}]

    rule_parameters_scenario1='{"keyIds":"arn:aws:kms:us-east-1:305333956852:key/ae25566a-c0d4-4ed2-8131-7c98e9487e3d, arn:als:kms:us-east-1:305333956852:keys/ae25566a-c0d4-4ed2-8131-7c98e9487e3d"}'
    def test_scenario1(self):
        SAGEMAKER_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": SAGEMAKER_CLIENT_MOCK,
            "paginate.return_value": self.list_endpoints_scenario1})
        SAGEMAKER_CLIENT_MOCK.describe_endpoint_config=MagicMock(side_effect=self.describe_endpoint_config_scenario1)
        lambda_event = build_lambda_scheduled_event(rule_parameters=self.rule_parameters_scenario1)
        response = rule.lambda_handler(lambda_event, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', customerErrorMessage='The KMS Key id should be in the right format.')

     

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
