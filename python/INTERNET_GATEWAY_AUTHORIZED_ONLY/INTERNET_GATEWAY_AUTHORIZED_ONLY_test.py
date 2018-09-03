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
import json
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = "AWS::EC2::InternetGateway"

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('INTERNET_GATEWAY_AUTHORIZED_ONLY')

class SampleTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_Scenario_1_not_starting_with_vpc(self):
        rule_parameters = "{\"AuthorizedVpcIds\":\"somename, vpc-shruti\"}"
        vpc_id_igw = 'vpc-abcde'
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(vpc_id_igw), rule_parameters), {})
        assert_customer_error_response(self, response, customerErrorCode='InvalidParameterValueException', customerErrorMessage='The parameter (somename) does not start with vpc-')

    def test_Scenario_2_igw_not_attached_vpc(self):
        rule_parameters = "{\"AuthorizedVpcIds\":\"vpc-paranshu, vpc-shruti\"}"
        vpc_id_igw = ""
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(vpc_id_igw), rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'some-resource-id'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_3_AuthorizedVpcIds_not_configured(self):
        rule_parameters = ""
        vpc_id_igw = 'vpc-abcde'
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(vpc_id_igw), rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', annotation='This IGW is not attached to an authorized VPC.'))
        assert_successful_evaluation(self, response, resp_expected)


    def test_scenario_4_igw_no_authorized_vpc(self):
        rule_parameters = "{\"AuthorizedVpcIds\":\"vpc-paranshu, vpc-shruti\"}"
        vpc_id_igw = 'vpc-abcde'
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(vpc_id_igw), rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', annotation='This IGW is not attached to an authorized VPC.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_5_compliant(self):
        rule_parameters = "{\"AuthorizedVpcIds\":\"vpc-paranshu, vpc-shruti\"}"
        vpc_id_igw = 'vpc-shruti'
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(vpc_id_igw), rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'some-resource-id'))
        assert_successful_evaluation(self, response, resp_expected)

def build_invoking_event(invoking_event_igw):
    attachments = []
    if(len(invoking_event_igw)>0):
        attachments.append({
                "vpcId": invoking_event_igw,
                "state": "available"
        })
    invoking_event_iam_role_sample = {
    "configurationItem": {
        "relatedEvents": [],
        "relationships": [],
        "configuration": {
            "internetGatewayId": "igw-a5f227c1",
            "attachments": attachments,
            "tags": []
        },
        "tags": {},
        "configurationItemCaptureTime": "2018-07-02T03:37:52.418Z",
        "awsAccountId": "633141505637",
        "configurationItemStatus": "ResourceDiscovered",
        "resourceType": "AWS::EC2::InternetGateway",
        "resourceId": "some-resource-id",
        "resourceName": "some-resource-name",
        "ARN": "some-arn"
    },
    "notificationCreationTime": "2018-07-02T23:05:34.445Z",
    "messageType": "ConfigurationItemChangeNotification"
    }
    return json.dumps(invoking_event_iam_role_sample)

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
