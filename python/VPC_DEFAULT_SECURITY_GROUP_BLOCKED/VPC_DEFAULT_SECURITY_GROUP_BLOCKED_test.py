#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import unittest

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import sys
import json

AWS_CONFIG_CLIENT_MOCK = MagicMock()
AWS_STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return AWS_CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return AWS_STS_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")


sys.modules['boto3'] = Boto3Mock()

RULE = __import__('VPC_DEFAULT_SECURITY_GROUP_BLOCKED')


#TODO
    # make response builder
    # Gherkin Scenario number

def buildLambdaEvent(invoking_event='{}', leftScope=False):
    return ({'accountId': '123456789012',
             'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
             'configRuleId': 'config-rule-8fngan',
             'configRuleName': 'default_sg_blocked',
             'eventLeftScope': leftScope,
             'executionRoleArn': 'arn:aws:iam::123456789012:role/service-role/config-role',
             'invokingEvent': invoking_event,
             'resultToken': 'TESTMODE',
             'version': '1.0'})


def build_invoking_event(configurationItemStatus, groupName, ip_ingress=[], ip_egress=[]):
    invoking_event = {"notificationCreationTime": "SomeTime",
                      "messageType": "SomeType",
                      "configurationItem": {
                          "resourceType": "AWS::EC2::SecurityGroup",
                          "configurationItemStatus": configurationItemStatus,
                          "resourceId": "sg-abab1212",
                          "configurationItemCaptureTime": "2018-02-20T06:56:55.533Z",
                          "configuration": {
                              "groupName": groupName,
                              "ipPermissions": ip_ingress,
                              "ipPermissionsEgress": ip_egress
                          }
                      }
                      }
    return json.dumps(invoking_event)


class Test_Compliance(unittest.TestCase):
    def test_NotApplicable_NonDefault(self):
        response = RULE.lambda_handler(
            buildLambdaEvent(build_invoking_event("ResourceDiscovered", "not-a-default-group")), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceId': 'sg-abab1212',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NotApplicable_Deleted_NonDefault(self):
        response = RULE.lambda_handler(
            buildLambdaEvent(build_invoking_event("ResourceDeleted", "not-a-default-group"), True), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceId': 'sg-abab1212',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NotApplicable_Deleted_Default(self):
        response = RULE.lambda_handler(buildLambdaEvent(build_invoking_event("ResourceDeleted", "default"), True), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceId': 'sg-abab1212',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Default_Ingress(self):
        response = RULE.lambda_handler(
            buildLambdaEvent(build_invoking_event("ResourceDiscovered", "default", "some-ingress")), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceId': 'sg-abab1212',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'OrderingTimestamp': 'datetime',
            'Annotation': 'This default Security Group has one or more Ingress rules.'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Default_egress(self):
        response = RULE.lambda_handler(
            buildLambdaEvent(build_invoking_event("ResourceDiscovered", "default", [], "some-egress")), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceId': 'sg-abab1212',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'OrderingTimestamp': 'datetime',
            'Annotation': 'This default Security Group has one or more Egress rules.'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_Compliant_Default(self):
        response = RULE.lambda_handler(buildLambdaEvent(build_invoking_event("ResourceDiscovered", "default")), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'COMPLIANT',
            'ComplianceResourceId': 'sg-abab1212',
            'ComplianceResourceType': 'AWS::EC2::SecurityGroup',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)


def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    testClass.assertEquals(evaluations_count, len(response))
    for counter, value in enumerate(response):
        testClass.assertEquals(resp_expected[counter]['ComplianceType'], value['ComplianceType'])
        testClass.assertEquals(resp_expected[counter]['ComplianceResourceType'], value['ComplianceResourceType'])
        testClass.assertEquals(resp_expected[counter]['ComplianceResourceId'], value['ComplianceResourceId'])
        testClass.assertTrue(value['OrderingTimestamp'])
        if 'Annotation' in resp_expected[counter]:
            testClass.assertEquals(resp_expected[counter]['Annotation'], value['Annotation'])
