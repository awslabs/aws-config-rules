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
import json

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

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

rule = __import__('EC2_TAG_MATCHES_INSTANCE_PROFILE_NAME')

class SampleTest(unittest.TestCase):

    # Scenario 1 : EC2 instance has no tag with key equal to TAG_KEY.
    def test_rule_scenario1(self):
        invoking_event = build_invoking_event("",None)
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("NOT_APPLICABLE", "some-resource-id"))
        assert_successful_evaluation(self, response, expected_response)
    
    # Scenario 2 : EC2 instance does not have TAG_VALUE_MUST_INCLUDE in tag value and has no instance profile.
    def test_rule_scenario2(self):
        application_role = {"application_role": "blah"}
        invoking_event = build_invoking_event(application_role,None)
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("NOT_APPLICABLE", "some-resource-id"))
        assert_successful_evaluation(self, response, expected_response)
    
    # Scenario 3 : EC2 instance does not have TAG_VALUE_MUST_INCLUDE in tag value and instance profile does not have NAME_ROLE_MUST_INCLUDE in IAM instance profile
    def test_rule_scenario3(self):
        application_role = {"application_role": "blah"}
        instance_profile = {"arn": "arn:aws:iam::123456789012:instance-profile/aws-poc.np.non-db.ec2role.iaminstancerole"}
        invoking_event = build_invoking_event(application_role, instance_profile)
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("NOT_APPLICABLE", "some-resource-id"))
        assert_successful_evaluation(self, response, expected_response)
    
    # Scenario 4 : EC2 instance does not have TAG_VALUE_MUST_INCLUDE in tag value but has NAME_ROLE_MUST_INCLUDE in IAM instance profile   
    def test_rule_scenario4(self):
        application_role = {"application_role": "blah"}
        instance_profile = {"arn": "arn:aws:iam::123456789012:instance-profile/aws-poc.np.db.ec2role.iaminstancerole"}
        invoking_event = build_invoking_event(application_role, instance_profile)
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("NON_COMPLIANT", "some-resource-id", annotation="Tag value for 'application_role' doesn't have 'DB' but IAM Instance Profile has '.db.'"))
        assert_successful_evaluation(self, response, expected_response)
    
    # Scenario 5 : EC2 instance has TAG_VALUE_MUST_INCLUDE in tag value but does not have an IAM instance profile
    def test_rule_scenario5(self):
        application_role = {"application_role": "DB/APP"}
        instance_profile = None
        invoking_event = build_invoking_event(application_role, instance_profile)
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("NON_COMPLIANT", "some-resource-id", annotation="Tag value for 'application_role' has 'DB' but there is no IAM instance profile for the resource"))
        assert_successful_evaluation(self, response, expected_response)
        
    # Scenario 6 : EC2 instance has TAG_VALUE_MUST_INCLUDE in tag value but does not have NAME_ROLE_MUST_INCLUDE in IAM instance profile
    def test_rule_scenario6(self):
        application_role = {"application_role": "DB/APP"}
        instance_profile = {"arn": "arn:aws:iam::123456789012:instance-profile/aws-poc.np.non-db.ec2role.iaminstancerole"}
        invoking_event = build_invoking_event(application_role, instance_profile)        
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("NON_COMPLIANT", "some-resource-id", annotation="Tag value for 'application_role' has 'DB' but IAM Instance Profile doesn't have '.db.'"))
        assert_successful_evaluation(self, response, expected_response)
        
    # Scenario 7 : EC2 instance has TAG_VALUE_MUST_INCLUDE in tag value and NAME_ROLE_MUST_INCLUDE in IAM instance profile
    def test_rule_scenario7(self):
        application_role = {"application_role": "DB/APP"}
        instance_profile = {"arn": "arn:aws:iam::123456789012:instance-profile/aws-poc.np.db.ec2role.iaminstancerole"}
        invoking_event = build_invoking_event(application_role, instance_profile)
        response = rule.lambda_handler(build_lambda_event(ruleParameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("COMPLIANT", "some-resource-id"))
        assert_successful_evaluation(self, response, expected_response)

####################
# Helper Functions #
####################

def build_lambda_event(ruleParameters, invoking_event):
    return {
        'executionRoleArn': 'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'ruleParameters': ruleParameters,
        'accountId': 'account-id',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken': 'token',

    }

def build_invoking_event(tags, iamInstanceProfileARN):
    invoking_event = {
        "messageType":"ConfigurationItemChangeNotification",
        "configurationItem":{
            "resourceType":"AWS::EC2::Instance",
            "resourceId": "some-resource-id",
            "configurationItemStatus": "OK",
            "configurationItemCaptureTime": "anytime",
            "tags":  tags,
            "configuration": { "iamInstanceProfile": iamInstanceProfileARN }
        }
    }
    return json.dumps(invoking_event)

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
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
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                testClass.assertEquals(response_expected['Annotation'], response[i]['Annotation'])