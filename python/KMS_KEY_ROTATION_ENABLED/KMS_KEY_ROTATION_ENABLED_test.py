#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
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
DEFAULT_RESOURCE_TYPE = 'AWS::KMS::Key'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
kms_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'kms':
            return kms_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('KMS_KEY_ROTATION_ENABLED')

class TestErrors(unittest.TestCase):
    def test_invalid_notification(self):
        sts_mock()
        response = rule.lambda_handler({'executionRoleArn':'roleArn','eventLeftScope': False,'invokingEvent':'{"messageType":"invalid-type"}','ruleParameters':'{}','accountId':'account-id','configRuleArn':'rule-arn'}, {})
        assert_customer_error_response(self, response)

    def test_customer_kms_listKeys_api_error(self):
        kms_client_mock.list_keys = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'400','Message':'PermissionDenied'}},'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, '400')
        
    def test_service_kms_listKeys_api_error(self):
        kms_client_mock.list_keys = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'500','Message':'service-error'}},'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, 'InternalError')

    listkeys_valid = {'Keys':[{ 'KeyId': 'key-string'}]}
    
    def test_customer_kms_describeKey_api_error(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'400','Message':'PermissionDenied'}},'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, '400')
        
    def test_service_kms_describeKey_api_error(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'500','Message':'service-error'}},'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, 'InternalError')

    describekey_customer_managed_kms_enabled = { 'KeyMetadata': {
        'Enabled': True,
        'Origin': 'AWS_KMS',
        'KeyManager': 'CUSTOMER'
    }}

    def test_customer_kms_getkeyrotationstatus_api_error(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_enabled)
        kms_client_mock.get_key_rotation_status = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'400','Message':'PermissionDenied'}},'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, '400')
        
    def test_service_kms_getkeyrotationstatus_api_error(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_enabled)
        kms_client_mock.get_key_rotation_status = MagicMock(side_effect=botocore.exceptions.ClientError({'Error':{'Code':'500','Message':'service-error'}},'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_customer_error_response(self, response, 'InternalError')

class TestScheduledNotification(unittest.TestCase):

    listkeys_empty = {'Keys': []}
    listkeys_valid = {'Keys':[{ 'KeyId': 'key-string'}]}
    listkeys_valid_multiple = {'Keys':[{ 'KeyId': 'key-string'},{ 'KeyId': 'key2-string'}]}

    describekey_aws_managed = { 'KeyMetadata': {
        'KeyManager': 'AWS'
    }}
    describekey_customer_managed_external = { 'KeyMetadata': {
        'Origin': 'EXTERNAL',
        'KeyManager': 'CUSTOMER'
    }}
    describekey_customer_managed_kms_disabled = { 'KeyMetadata': {
        'Enabled': False,
        'Origin': 'AWS_KMS',
        'KeyManager': 'CUSTOMER'
    }}
    describekey_customer_managed_kms_enabled = { 'KeyMetadata': {
        'Enabled': True,
        'Origin': 'AWS_KMS',
        'KeyManager': 'CUSTOMER'
    }}

    getkeyrotationstatus_enabled = {'KeyRotationEnabled': True}
    getkeyrotationstatus_disabled = {'KeyRotationEnabled': False}
    
    eval_empty = {'EvaluationResults': []}
                    
    def test_compliance_NoKMS(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_empty)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', compliance_resource_type='AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)     
    
    def test_compliance_NoKMSOriginatedCustomerManaged(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid_multiple)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_aws_managed)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', compliance_resource_type='AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)
        
    def test_compliance_ExternalOriginatedCustomerManaged(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_external)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', compliance_resource_type='AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_KMSOriginatedCustomerManagedNotEnabled(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_disabled)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'key-string'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_KMSOriginatedCustomerManagedEnabledwoRotation(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_enabled)
        kms_client_mock.get_key_rotation_status= MagicMock(return_value=self.getkeyrotationstatus_disabled)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'key-string', annotation='The yearly rotation is not activated for key with ID "key-string".'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_compliance_KMSOriginatedCustomerManagedEnabledwRotation(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_enabled)
        kms_client_mock.get_key_rotation_status= MagicMock(return_value=self.getkeyrotationstatus_enabled)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'key-string'))
        assert_successful_evaluation(self, response, resp_expected)
        
    def test_compliance_KMSOriginatedCustomerManagedEnabledwRotation_Multiple(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid_multiple)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_enabled)
        kms_client_mock.get_key_rotation_status= MagicMock(return_value=self.getkeyrotationstatus_enabled)
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=self.eval_empty)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'key-string'))
        resp_expected.append(build_expected_response('COMPLIANT', 'key2-string'))
        assert_successful_evaluation(self, response, resp_expected, 2)

class TestScheduledDeletion(unittest.TestCase): 
    listkeys_valid_multiple = {'Keys':[{ 'KeyId': 'key-string'},{ 'KeyId': 'key2-string'}]}
    describekey_customer_managed_kms_enabled = { 'KeyMetadata': {
        'Enabled': True,
        'Origin': 'AWS_KMS',
        'KeyManager': 'CUSTOMER'
    }}
    getkeyrotationstatus_enabled = {'KeyRotationEnabled': True}
    
    def test_compliance_KMS_key_deleted_handling(self):
        kms_client_mock.list_keys = MagicMock(return_value=self.listkeys_valid_multiple)
        kms_client_mock.describe_key = MagicMock(return_value=self.describekey_customer_managed_kms_enabled)
        kms_client_mock.get_key_rotation_status= MagicMock(return_value=self.getkeyrotationstatus_enabled)
        old_eval = {'EvaluationResults': [
            {'EvaluationResultIdentifier': {'EvaluationResultQualifier': {'ResourceId': 'key2-string'}}},
            {'EvaluationResultIdentifier': {'EvaluationResultQualifier': {'ResourceId': 'key3-string'}}}]}
        config_client_mock.get_compliance_details_by_config_rule = MagicMock(return_value=old_eval)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'key3-string'))
        resp_expected.append(build_expected_response('COMPLIANT', 'key-string'))
        resp_expected.append(build_expected_response('COMPLIANT', 'key2-string'))
        assert_successful_evaluation(self, response, resp_expected, 3)

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
# Commun Testing #
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