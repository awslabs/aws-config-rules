import sys
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
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EC2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'sts':
            return STS_CLIENT_MOCK
        elif client_name == 'ec2_client':
            return EC2_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('CHECK_ROOT_VOLUME_ENCRYPTION')

# Checks for scenario wherein no non-compliant resources are present
class NoResourcesTest(unittest.TestCase):
    def test_scenario_1_compliant_resources(self):
        describe_instances_result = {"Reservations":[{"Instances":[],},]}
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='NOT_APPLICABLE', compliance_resource_id='123456789012')]
        assert_successful_evaluation(self, response, expected_response, len(response))


#### Checks for scenario wherein non-compliant resources are present ####

class NonCompliantResourcesTest(unittest.TestCase):
    #Non-encrypted root volume with single attachments
    def test_scenario_2_non_compliant_resources(self):
        describe_instances_result = '{"Reservations":[{"Instances":[{"InstanceId":"i-06bad741b9fef89c0","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"vol-0746fccf419d8f2fc",}}],"RootDeviceName":"/dev/sda1",}],},]}'
        describe_volumes_result = '{"Volumes":[{"Encrypted":false,"VolumeId":"vol-0746fccf419d8f2fc",},]}'
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='NON_COMPLIANT', compliance_resource_id='i-06bad741b9fef89c0', annotation='Non-compliant. Root volume is not encrypted.')]
        assert_successful_evaluation(self, response, expected_response, len(response))
    #Non-encrypted root volume with multiple encrypted attachments
    def test_scenario_3_non_compliant_resources(self):
        describe_instances_result = '{"Reservations":[{"Instances":[{"InstanceId":"i-06bad741b9fef89c0","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"vol-0746fccf419d8f2fc",}},{"DeviceName":"/dev/sda2","Ebs":{"VolumeId":"vol-0a016639d587e69f3",}},{"DeviceName":"/dev/sda3","Ebs":{"VolumeId":"vol-0a016756d587e23f1",}}],"RootDeviceName":"/dev/sda1",}],},]}'
        describe_volumes_result = '{"Volumes":[{"Encrypted":false,"VolumeId":"vol-0746fccf419d8f2fc",},{"Encrypted":true,"VolumeId":"vol-0a016639d587e69f3",},{"Encrypted":true,"VolumeId":"vol-0a016756d587e23f1",}]}'
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='NON_COMPLIANT', compliance_resource_id='i-06bad741b9fef89c0', annotation='Non-compliant. Root volume is not encrypted.')]
        assert_successful_evaluation(self, response, expected_response, len(response))
    #Non-encrypted root volume with multiple non-encrypted attachments
    def test_scenario_4_non_compliant_resources(self):
        describe_instances_result = '{"Reservations":[{"Instances":[{"InstanceId":"i-06bad741b9fef89c0","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"vol-0746fccf419d8f2fc",}},{"DeviceName":"/dev/sda4","Ebs":{"VolumeId":"vol-0a286456d004e08h9",}},{"DeviceName":"/dev/sda5","Ebs":{"VolumeId":"vol-5536fhcf911d8f2js",}}],"RootDeviceName":"/dev/sda1",}],},]}'
        describe_volumes_result = '{"Volumes":[{"Encrypted":false,"VolumeId":"vol-0746fccf419d8f2fc",},{"Encrypted":false,"VolumeId":"vol-0a286456d004e08h9",},{"Encrypted":false,"VolumeId":"vol-5536fhcf911d8f2js",}]}'
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='NON_COMPLIANT', compliance_resource_id='i-06bad741b9fef89c0', annotation='Non-compliant. Root volume is not encrypted.')]
        assert_successful_evaluation(self, response, expected_response, len(response))

class CompliantResourcesTest(unittest.TestCase):
    #Encrypted root volume with single encrypted attachments
    def test_scenario_1_compliant_resources(self):
        describe_instances_result = '{"Reservations":[{"Instances":[{"InstanceId":"i-06bad741b9fef89c0","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"vol-0a016639d587e69f3",}}],"RootDeviceName":"/dev/sda1",}],},]}'
        describe_volumes_result = '{"Volumes":[{"Encrypted":true,"VolumeId":"vol-0a016639d587e69f3",},]}'
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='COMPLIANT', compliance_resource_id='i-06bad741b9fef89c0', annotation='Compliant. Root volume is encrypted.')]
        assert_successful_evaluation(self, response, expected_response, len(response))
    #Encrypted root volume with multiple encrypted attachments
    def test_scenario_2_compliant_resources(self):
        describe_instances_result = '{"Reservations":[{"Instances":[{"InstanceId":"i-06bad741b9fef89c0","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"vol-0a016639d587e69f3",}}],"RootDeviceName":"/dev/sda1",}],},]}'
        describe_volumes_result = '{"Volumes":[{"Encrypted":true,"VolumeId":"vol-0a016639d587e69f3",},{"Encrypted":true,"VolumeId":"vol-0a016756d587e23f1",},{"Encrypted":true,"VolumeId":"vol-1f244376d396d23n4",}]}'
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='COMPLIANT', compliance_resource_id='i-06bad741b9fef89c0', annotation='Compliant. Root volume is encrypted.')]
        assert_successful_evaluation(self, response, expected_response, len(response))
    #Encrypted root volume with multiple non-encrypted attachments
    def test_scenario_3_compliant_resources(self):
        describe_instances_result = '{"Reservations":[{"Instances":[{"InstanceId":"i-06bad741b9fef89c0","BlockDeviceMappings":[{"DeviceName":"/dev/sda1","Ebs":{"VolumeId":"vol-0a016639d587e69f3",},},{"DeviceName":"/dev/sda8","Ebs":{"VolumeId":"vol-0746fccf419d8f2fc",}},{"DeviceName":"/dev/sda9","Ebs":{"VolumeId":"vol-0a286456d004e08h9",}}],"RootDeviceName":"/dev/sda1",}],},]}'
        describe_volumes_result = '{"Volumes":[{"Encrypted":true,"VolumeId":"vol-0a016639d587e69f3",},{"Encrypted":false,"VolumeId":"vol-0746fccf419d8f2fc",},{"Encrypted":false,"VolumeId":"vol-0a286456d004e08h9",}]}'
        EC2_CLIENT_MOCK.describe_instances = MagicMock(return_value=describe_instances_result)
        EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='COMPLIANT', compliance_resource_id='i-06bad741b9fef89c0', annotation='Compliant. Root volume is encrypted.')]
        assert_successful_evaluation(self, response, expected_response, len(response))


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
