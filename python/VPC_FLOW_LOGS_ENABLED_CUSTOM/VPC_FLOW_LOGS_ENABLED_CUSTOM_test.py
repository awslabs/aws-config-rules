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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
ec2_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'ec2':
            return ec2_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('VPC_FLOW_LOGS_ENABLED_CUSTOM')

class ParameterTests(unittest.TestCase):
    # Check for any invalid parameter (such as "traffictype" instead of "TrafficType")
    def test_error_invalid_parameter_name(self):
        ec2_client_mock.reset_mock(return_value=True)
        
        ruleParam = '{"traffictype": "ACCEPT"}'
        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)

        response = rule.lambda_handler(lambdaEvent, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    # Check for any invalid parameter values (such as TrafficType as "ALLOW" instead of "ACCEPT")
    def test_invalid_traffictype_parameter_value(self):
        ec2_client_mock.reset_mock(return_value=True)
        
        ruleParam = '{"TrafficType": "ALLOW"}'
        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)

        response = rule.lambda_handler(lambdaEvent, {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')


    # Check for invalid parameter values of WhiteListedVPC
    def test_error_invalid_vpc_parameter_value(self):
        ec2_client_mock.reset_mock(return_value=True)
        
        ruleParam = '{"WhiteListedVPC": "vpc-asd123, vpc_1234rd", "TrafficType": "ALLOW"}'
        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)

        response = rule.lambda_handler(lambdaEvent, {}) 
        assert_customer_error_response(self, response, 'InvalidParameterValueException')
        

class ComplianceTests(unittest.TestCase):
    # Check for VPC has flow logs enabled with TrafficType as ALL and no parameter provided
    def test_COMPLIANT_Flow_Log_Enabled_TrafficType_ALL(self):
        ec2_client_mock.reset_mock(return_value=True)
        
        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": [{"ResourceId": "vpc-asd123", "TrafficType": "ALL"}]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)

        lambdaEvent = build_lambda_scheduled_event(rule_parameters='{}')
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC'
            })
        assert_successful_evaluation(self, response, resp_expected)


    # Check for VPC does not have flow logs enabled and no parameter provided
    def test_NONCOMPLIANT_Flow_Log_Not_Enabled(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": []}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)

        lambdaEvent = build_lambda_scheduled_event(rule_parameters='{}')
        response = rule.lambda_handler(lambdaEvent, {})
        print(response)
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'No flow log has been configured.'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for VPC has flow logs enabled but TrafficType is not ALL and noparameter provided
    def test_NONCOMPLIANT_Flow_Log_Enabled_TrafficType_Not_ALL(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": [{"ResourceId": "vpc-asd123", "TrafficType": "REJECT"}]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)

        lambdaEvent = build_lambda_scheduled_event(rule_parameters='{}')
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'No flow log matches with the traffic type ALL.'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for VPC is in WhiteListedVPC parameter
    def test_COMPLIANT_VPC_Whitelisted(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        ruleParam = '{"WhiteListedVPC": "vpc-asd123"}'

        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'This is a WhiteListed VPC.'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for Rule parameter TrafficType ACCEPT and VPC has flow logs enabled with TrafficType as ACCEPT
    def test_COMPLIANT_Flow_Log_Enabled_TrafficType_ACCEPT_TrafficTypeParam_ACCEPT(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": [{"ResourceId": "vpc-asd123", "TrafficType": "ACCEPT"}]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)
        ruleParam = '{"TrafficType": "ACCEPT"}'

        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for Rule Parameter TrafficType ACCEPT and vpc Flow log enabled with traffic type as ALL
    def test_NONCOMPLIANT_Flow_Log_Enabled_TrafficType_ALL_TrafficTypeParam_ACCEPT(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": [{"ResourceId": "vpc-asd123", "TrafficType": "ALL"}]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)
        ruleParam = '{"TrafficType": "ACCEPT"}'

        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'No flow log matches with the traffic type ACCEPT.'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for Rule parameter TrafficType ACCEPT and VPC has flow logs enabled with TrafficType as ACCEPT
    def test_NONCOMPLIANT_Flow_Log_Enabled_TrafficType_ACCEPT_TrafficTypeParam_ACCEPT_LogGroup_Wrong(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": [{"ResourceId": "vpc-asd123", "TrafficType": "ACCEPT", "LogGroupName": "some-other-log-group"}]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)
        ruleParam = '{"TrafficType": "ACCEPT", "LogGroupName": "my-log-group"}'

        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'No flow log matches with the log group name my-log-group.'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for Rule parameter TrafficType ACCEPT and VPC has flow logs enabled with TrafficType as ACCEPT
    def test_NONCOMPLIANT_Flow_Log_Enabled_TrafficType_ACCEPT_TrafficTypeParam_ACCEPT_LogGroup_Good_with_Error(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123", "CidrBlock": "10.10.0.0/16"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value = Des_VPC)
        Des_Flow = {"FlowLogs": [{"ResourceId": "vpc-asd123", "TrafficType": "ACCEPT", "LogGroupName": "my-log-group", "DeliverLogsErrorMessage": "Access error"}]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value = Des_Flow)
        ruleParam = '{"TrafficType": "ACCEPT", "LogGroupName": "my-log-group"}'

        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'The following error occured in the flow log delivery: Access error.'
            })
        assert_successful_evaluation(self, response, resp_expected)

    # Check for multiple VPC with a whitelisted VPC, parameter traffic_type as ACCEPT, a VPC which has flow log enabled as ACCEPT, a VPC which FlowLog is ALL
    def test_COMPLIANT_and_NONCOMPLIANT_mutiple_VPC(self):
        ec2_client_mock.reset_mock(return_value=True)

        Des_VPC = {"Vpcs": [{"VpcId": "vpc-asd123"}, {"VpcId": "vpc-pqr296"}, {"VpcId": "vpc-xyz984"}, {"VpcId": "vpc-13e48c77"}, {"VpcId": "vpc-zxc234"}]}
        ec2_client_mock.describe_vpcs = MagicMock(return_value=Des_VPC)
        Des_Flow = {"FlowLogs": [
            {"ResourceId": "vpc-xyz984", "TrafficType": "ACCEPT"},
            {"ResourceId": "vpc-13e48c77", "TrafficType": "ALL"},
            {"ResourceId": "vpc-zxc234", "TrafficType": "ACCEPT", "DeliverLogsErrorMessage": "Access error"}
            ]}
        ec2_client_mock.describe_flow_logs = MagicMock(return_value=Des_Flow)
        ruleParam = '{"WhiteListedVPC": "vpc-pqr296, vpc-15045371", "TrafficType": "ACCEPT"}'

        lambdaEvent = build_lambda_scheduled_event(rule_parameters=ruleParam)
        response = rule.lambda_handler(lambdaEvent, {})
        resp_expected = []
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-asd123',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'No flow log has been configured.'
            })
        resp_expected.append({
                'ComplianceType': 'COMPLIANT',
                'ComplianceResourceId': 'vpc-pqr296',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'This is a WhiteListed VPC.'
            })
        resp_expected.append({
                'ComplianceType': 'COMPLIANT',
                'ComplianceResourceId': 'vpc-xyz984',
                'ComplianceResourceType': 'AWS::EC2::VPC'
            })
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-13e48c77',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'No flow log matches with the traffic type ACCEPT.'
            })
        resp_expected.append({
                'ComplianceType': 'NON_COMPLIANT',
                'ComplianceResourceId': 'vpc-zxc234',
                'ComplianceResourceType': 'AWS::EC2::VPC',
                'Annotation': 'The following error occured in the flow log delivery: Access error.'
            })
        print(response)
        print(resp_expected)
        assert_successful_evaluation(self, response, resp_expected, 5)

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
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
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