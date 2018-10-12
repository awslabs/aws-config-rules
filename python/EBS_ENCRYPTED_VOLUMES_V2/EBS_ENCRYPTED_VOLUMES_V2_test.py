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

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Volume'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
ec2_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'ec2':
            return ec2_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('EBS_ENCRYPTED_VOLUMES_V2')


def getRuleParameters(validity, paramName=None):
    validParameters = {
        "VolumeExceptionList": "vol-01",
        "SubnetExceptionList": "subnet-01",
        "KmsIdList": "415ee9cc-9beb-4217-bec8-45cabmfrbee6f"
    }
    invalidVolumeParams = [
        "vol-050607259f67717d5, asdef",
        "1234",
        "vol23r4ts",
        "vol-948567,vol- 246934, vol-235646 vol-35446"
    ]
    invalidKmsKeyIdParams = [
        "-9beb-4217-bec8-45cab7ase6f",
        "415ee9cc-9beb-4217-bec8-45cab7abee6f,415ee9cc9beb4217bec845cab7abee6f",
        "415ee9cc-9beb-4217-bec8-",
        "415ee9cc-9beb-4217-bec8-asff--sdvrvbrv"
    ]
    invalidSubnetParams = [
        'subnetd2cd14ba',
        'd2cd14ba',
        'subnet-d2cd14ba subnet-d2cd1443',
        'd2cd14ba-subnet'
    ]
    if not validity:
        if paramName == 'VolumeExceptionList':
            return invalidVolumeParams
        if paramName == 'SubnetExceptionList':
            return invalidSubnetParams
        if paramName == 'KmsIdList':
            return invalidKmsKeyIdParams
    return validParameters

def constructConfiguration(encrypted, volumeId, kmsKeyId=None, attachments=''):
    return {
        "encrypted":encrypted,
        "kmsKeyId":kmsKeyId,
        "volumeId":volumeId,
        "attachments":attachments
    }

def constructConfigItem(configuration, volumeId):
    configItem = {
        'relatedEvents': [],
        'relationships': [],
        'configuration': configuration,
        'configurationItemVersion': "1.3",
        'configurationItemCaptureTime': "2018-07-02T03:37:52.418Z",
        'supplementaryConfiguration': {},
        'configurationStateId': 1532049940079,
        'awsAccountId': "SAMPLE",
        'configurationItemStatus': "ResourceDiscovered",
        'resourceType': "AWS::EC2::Volume",
        'resourceId': volumeId,
        'resourceName': None,
        'ARN': "arn:aws:ec2:ap-south-1:822333706:volume/{}".format(volumeId),
        'awsRegion': "ap-south-1",
        'configurationStateMd5Hash': "",
        'resourceCreationTime': "2018-07-19T06:27:28.289Z",
        'tags': {}
    }
    return configItem

def constructInvokingEvent(configItem):
    invokingEvent = {
        "configurationItemDiff": None,
        "configurationItem": configItem,
        "notificationCreationTime": "SAMPLE",
        "messageType": "ConfigurationItemChangeNotification",
        "recordVersion": "SAMPLE"
    }
    return invokingEvent

class InvalidParametersTest(unittest.TestCase):

    def test_Scenario_1_invalid_kmsKeyParameters(self):
        params = {"KmsIdList": "-1,s30c-du4-3erdft-"}
        configuration = constructConfiguration(encrypted=True, kmsKeyId='sdf434-dsvfb3-4545-dfvfdv', volumeId="vol-w4t4434")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "volumeId"))
        lambdaEvent = build_lambda_configurationchange_event(invoking_event=invoking_event, rule_parameters=params)
        response = rule.lambda_handler(lambdaEvent, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_Scenario_2_invalid_volumeParameters(self):
        params = {"VolumeExceptionList": "oool-0003,vol--0sd4e"}
        configuration = constructConfiguration(encrypted=True, kmsKeyId='sdf434-dsvfb3-4545-dfvfdv', volumeId="vol-w4t4434")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "volumeId"))
        lambdaEvent = build_lambda_configurationchange_event(invoking_event=invoking_event, rule_parameters=params)
        response = rule.lambda_handler(lambdaEvent, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_Scenario_3_invalid_subnetParameters(self):
        params = {"SubnetExceptionList": "aaasssubnet-02,subnet03edfy45,dhu47dh-subnet"}
        configuration = constructConfiguration(encrypted=True, kmsKeyId='sdf434-dsvfb3-4545-dfvfdv', volumeId="vol-w4t4434")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "volumeId"))
        lambdaEvent = build_lambda_configurationchange_event(invoking_event=invoking_event, rule_parameters=params)
        response = rule.lambda_handler(lambdaEvent, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

class ComplianceTest(unittest.TestCase):

    def test_Scenario_4_volumeinVolumeExceptionList(self):
        rule_parameters = getRuleParameters(True, '')
        configuration = constructConfiguration(encrypted=False, volumeId="vol-01")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-01"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'COMPLIANT',
            'vol-01',
            annotation='This EBS volume is part of the exception list.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_6_volumeencrypted_noKMSparam(self):
        rule_parameters = {"VolumeExceptionList": "vol-0003", "SubnetExceptionList": "subnet-01"}
        configuration = constructConfiguration(encrypted=True, kmsKeyId='sdf434-dsvfb3-4545-dfvfdv', volumeId="vol-01")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-01"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'COMPLIANT',
            'vol-01'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_5_volumeNOTencrypted_noKMSparam(self):
        rule_parameters = {"VolumeExceptionList": "vol-0003", "SubnetExceptionList": "subnet-01"}
        configuration = constructConfiguration(encrypted=False, volumeId="vol-01")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-01"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'NON_COMPLIANT',
            'vol-01'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_7_volumeencrypted_KMSKeyInvalid(self):
        rule_parameters = getRuleParameters(True, '')
        configuration = constructConfiguration(
            encrypted=True,
            kmsKeyId='arn:aws:kms:region-all-1:123456798877:key/sdf434-dsvfb3-4545-dfvfdv',
            volumeId="vol-02")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-02"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'NON_COMPLIANT',
            'vol-02',
            annotation='This EBS volume is encrypted, but not with a KMS Key listed in the parameter KmsIdList.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_8_volumeencrypted_KMSKeyValid(self):
        rule_parameters = getRuleParameters(True, '')
        configuration = constructConfiguration(
            encrypted=True,
            kmsKeyId='arn:aws:kms:region-all-1:123456798877:key/415ee9cc-9beb-4217-bec8-45cabmfrbee6f',
            volumeId="vol-02")
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-02"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'COMPLIANT',
            'vol-02'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_9_volumeSubnetinSubnetExceptionList(self):
        ec2_mock.describe_instances = MagicMock(return_value={"Reservations":[{"Instances":[{"NetworkInterfaces":[{"SubnetId":"subnet-02"}]}]}]})
        rule_parameters = {
            "VolumeExceptionList": "vol-0003",
            "SubnetExceptionList": "subnet-02",
            "KmsIdList": "115ff9cc-9beb-4517-bec8-45cabmfrbee6f"
        }
        configuration = constructConfiguration(encrypted=False, volumeId="vol-01", attachments=[{"instanceId":"i-02"}])
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-01"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'COMPLIANT',
            'vol-01',
            annotation='This EBS volume is attached to an EC2 instance in a subnet which is part the exception list.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_10_volumeNotEncrSubnetNotinSubnetList(self):
        ec2_mock.describe_instances = MagicMock(return_value={"Reservations":[{"Instances":[{"SubnetId":"subnet-02"}]}]})
        rule_parameters = getRuleParameters(True, '')
        configuration = constructConfiguration(encrypted=False, volumeId="vol-02", attachments=[{"instanceId":"i-02"}])
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-02"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'NON_COMPLIANT',
            'vol-02'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_11_volumeEncryptedNoKMSNoSubnetExceptionNoVolumeException(self):
        ec2_mock.describe_instances = MagicMock(return_value={"Reservations":[{"Instances":[{"SubnetId":"subnet-02"}]}]})
        rule_parameters = {"VolumeExceptionList": "vol-0003", "SubnetExceptionList": "subnet-01"}
        configuration = constructConfiguration(
            encrypted=True,
            kmsKeyId='arn:aws:kms:region-all-1:123456798877:key/415ee9cc-9beb-4217-bec8-45cabmfrbee6f',
            volumeId="vol-02",
            attachments=[{"instanceId":"i-02"}])
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-02"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'COMPLIANT',
            'vol-02'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_12_volumeEncryptedNotWithProperKMSNoSubnetExceptionNoVolumeException(self):
        ec2_mock.describe_instances = MagicMock(return_value={"Reservations":[{"Instances":[{"SubnetId":"subnet-02"}]}]})
        rule_parameters = {
            "VolumeExceptionList": "vol-0003",
            "SubnetExceptionList": "subnet-01",
            "KmsIdList": "115ff9cc-9beb-4517-bec8-45cabmfrbee6f"
        }
        configuration = constructConfiguration(
            encrypted=True,
            kmsKeyId='arn:aws:kms:region-all-1:123456798877:key/415ee9cc-9beb-4217-bec8-45cabmfrbee6f',
            volumeId="vol-02",
            attachments=[{"instanceId":"i-02"}])
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-02"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'NON_COMPLIANT',
            'vol-02',
            annotation='This EBS volume is encrypted, but not with a KMS Key listed in the parameter KmsIdList.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_13_volumeEncryptedWithProperKMSNoSubnetExceptionNoVolumeException(self): #Scenario13
        ec2_mock.describe_instances = MagicMock(return_value={"Reservations":[{"Instances":[{"SubnetId":"subnet-02"}]}]})
        rule_parameters = getRuleParameters(True, '')
        configuration = constructConfiguration(
            encrypted=True,
            kmsKeyId='arn:aws:kms:region-all-1:123456798877:key/415ee9cc-9beb-4217-bec8-45cabmfrbee6f',
            volumeId="vol-02",
            attachments=[{"instanceId":"i-02"}]
        )
        invoking_event = constructInvokingEvent(constructConfigItem(configuration, "vol-02asd"))
        event = build_lambda_configurationchange_event(invoking_event, rule_parameters)
        response = rule.lambda_handler(event, {})
        resp_expected = []
        resp_expected.append(build_expected_response(
            'COMPLIANT',
            'vol-02asd'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': json.dumps(invoking_event),
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = json.dumps(rule_parameters)
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
