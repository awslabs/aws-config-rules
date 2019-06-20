# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import sys
import unittest
from unittest.mock import MagicMock
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::SecurityGroup'

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

RULE = __import__('VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS')

class ComplianceTest(unittest.TestCase):

    def test_sg_no_port_open_to_world(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"10.0.0.0/0"}],"ipRanges":["10.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"11.0.0.0/0"}],"ipRanges":["11.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"15.0.0.0/0"}],"ipRanges":["15.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"25.25.0.0/0"}],"ipRanges":["25.25.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{"authorizedTcpPorts": "443","authorizedUdpPorts": "80"}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    def test_sg_no_port_open_to_world_and_no_authorized_tcp(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"11.0.0.0/0"}],"ipRanges":["11.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"15.0.0.0/0"}],"ipRanges":["15.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"25.25.0.0/0"}],"ipRanges":["25.25.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='No TCP port is authorized to be open, according to the authorizedTcpPorts parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_sg_no_port_open_to_world_and_no_authorized_udp(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"11.0.0.0/0"}],"ipRanges":["11.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"15.0.0.0/0"}],"ipRanges":["15.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"25.25.0.0/0"}],"ipRanges":["25.25.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='No UDP port is authorized to be open, according to the authorizedUdpPorts parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_one_udp_open_not_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTcpPorts": "443","authorizedUdpPorts": "80"}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='One or more UDP ports (10000) are not in range of the authorizedUdpPorts parameter (80).'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_one_tcp_open_not_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":12000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTcpPorts": "443","authorizedUdpPorts": "80"}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='One or more TCP ports (10000-12000) are not in range of the authorizedTcpPorts parameter (443).'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_one_udp_open_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTcpPorts": "443","authorizedUdpPorts": "10000","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    def test_one_tcp_open_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTcpPorts": "10000","authorizedUdpPorts": "80"}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    def test_tcp_and_udp_open_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":20000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}, {"fromPort":80,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":100,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTcpPorts": "10000-20000","authorizedUdpPorts": "80-100","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
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
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
