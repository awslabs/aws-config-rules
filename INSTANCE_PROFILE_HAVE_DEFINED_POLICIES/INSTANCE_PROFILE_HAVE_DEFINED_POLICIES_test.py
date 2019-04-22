#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import sys
import unittest
import json
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
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::Role'
POLICY_NAMES_THAT_MUST_BE_ATTACHED = ['AmazonEC2RoleforSSM', 'CloudWatchAgentServerPolicy', 'EC2InstanceDescribe', 'DBBackupBucket']

#############
# Main Code #
#############

config_client_mock = MagicMock()
iam_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        if client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('INSTANCE_PROFILE_HAVE_DEFINED_POLICIES')

class SampleTest(unittest.TestCase):

    def test_Scenario_1_IF_APPLICABLE_1(self):
        attachedManagedPolicies = populate_attachedManagedPolicies(4)
        resourceName = "test1.db.ec2role.test1"
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(resourceName, attachedManagedPolicies)), {})
        # print (response)
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'some-resource-id', 'AWS::IAM::Role'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_1_IF_APPLICABLE_2(self):
        attachedManagedPolicies = populate_attachedManagedPolicies(2)
        resourceName = "test1.ec2role.iaminstancerole.test1"
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(resourceName, attachedManagedPolicies)), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'some-resource-id', 'AWS::IAM::Role'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_2_NOT_INSTANCE_PROFILE_1(self):
        attachedManagedPolicies = []
        resourceName = "test1.db.ec2role.iaminstancerole.test1"
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(resourceName, attachedManagedPolicies)), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', 'AWS::IAM::Role', annotation='One or more mandatory policy is not attached to this instance profile.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_Scenario_3_IS_INSTANCE_PROFILE(self):
        attachedManagedPolicies = populate_attachedManagedPolicies(4)
        resourceName = "test1.db.ec2role.iaminstancerole.test1"
        response = rule.lambda_handler(build_lambda_configurationchange_event(build_invoking_event(resourceName, attachedManagedPolicies)), {})
        # print (response)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'some-resource-id', 'AWS::IAM::Role'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################
def build_invoking_event(resourceName, attachedManagedPolicies):
    invoking_event = {
        "messageType":"ConfigurationItemChangeNotification",
        "configurationItem":{
            "resourceType":"AWS::IAM::Role",
            "resourceId": "some-resource-id",
            "configurationItemStatus": "OK",
            "configurationItemCaptureTime": "anytime",
            "resourceName": resourceName,
            "configuration":{
                "attachedManagedPolicies": attachedManagedPolicies
                }
            }
    }
    return json.dumps(invoking_event)

def populate_attachedManagedPolicies(i):
    attachedManagedPolicies = []
    for policy in POLICY_NAMES_THAT_MUST_BE_ATTACHED[:i]:
        attachedManagedPolicies.append({
            "policyName": policy
        })
    return attachedManagedPolicies

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'INSTANCE_PROFILE_HAVE_DEFINED_POLICIES',
        'executionRoleArn':'arn:aws:config:ap-south-1:633141505637:config-rule/config-rule-m1ypfw',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '633141505637',
        'configRuleArn': 'arn:aws:config:ap-south-1:633141505637:config-rule/config-rule-m1ypfw',
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
        'eventLeftScope': True,
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
            print (response_expected)
            print (response[i])
            if 'Annotation' in response_expected and 'Annotation' in response[i]:
                testClass.assertEquals(response_expected['Annotation'], response[i]['Annotation'])
