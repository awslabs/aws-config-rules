# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import json
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
EC2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'ec2':
            return EC2_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EC2_INFRASTRUCTURE_TAG_MATCHING')

class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"TagName":"SecurityProfile","VPC":"True","SecurityGroups":"False","ENIs":"False","Subnet":"False","Volumes":"False"}'

    def test_sample(self):
        self.assertTrue(True)

    def test_rule_EC2_not_tagged(self):
        # The EC2 instance is not tagged with the "SecurityProfile" Tag. This config rule does not enforce tags => COMPLIANT
        rule_parameters = '{"TagName":"SecurityProfile","VPC":"True","SecurityGroups":"False","ENIs":"False","Subnet":"False","Volumes":"False"}'
        invoking_event = build_invoking_event()
        response = RULE.lambda_handler(build_lambda_configurationchange_event(rule_parameters=rule_parameters, invoking_event=invoking_event), "")
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'i-08849914c0be5c303')) 
        assert_successful_evaluation(self, response, resp_expected)

    def test_rule_resource_not_tagged(self):
        # In rule_parameters, VPC is set to True, but the VPC is not tagged. Since this Config rule does not enforce tags, this is evaluated as COMPLIANT.
        rule_parameters = '{"TagName":"SecurityProfile","VPC":"True","SecurityGroups":"False","ENIs":"False","Subnet":"False","Volumes":"False"}'
        invoking_event = build_invoking_event(tags = {"SecurityProfile":"Medium"})
        ec2_mock(Vpcs=[])
        response = RULE.lambda_handler(build_lambda_configurationchange_event(rule_parameters=rule_parameters, invoking_event=invoking_event), "")
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'i-08849914c0be5c303')) # This rule does not enforce tags!
        assert_successful_evaluation(self, response, resp_expected)

    def test_rule_tags_do_not_match_of_relevant_resources(self):
        # In rule_parameters, VPC is set to True, but the TagValue of the VPC does not match the TagValue of the EC2 = NON_COMPLIANT
        rule_parameters = '{"TagName":"SecurityProfile","VPC":"True","SecurityGroups":"False","ENIs":"False","Subnet":"False","Volumes":"False"}'
        invoking_event = build_invoking_event(tags = {"SecurityProfile":"Medium"})
        ec2_mock(Vpcs=[{"Key":"SecurityProfile","Value":"Low"}])
        response = RULE.lambda_handler(build_lambda_configurationchange_event(rule_parameters=rule_parameters, invoking_event=invoking_event), "")
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'i-08849914c0be5c303'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_rule_tags_do_not_match_of_not_relevant_resources(self):
        # In rule_parameters, VPC is set to False and the TagValue of the VPC does not match the TagValue of the EC2 => COMPLIANT
        rule_parameters = '{"TagName":"SecurityProfile","VPC":"False","SecurityGroups":"False","ENIs":"False","Subnet":"False","Volumes":"False"}'
        invoking_event = build_invoking_event(tags = {"SecurityProfile":"Medium"})
        ec2_mock(Vpcs=[{"Key":"SecurityProfile","Value":"Low"}])
        response = RULE.lambda_handler(build_lambda_configurationchange_event(rule_parameters=rule_parameters, invoking_event=invoking_event), "")
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'i-08849914c0be5c303'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_rule_tags_match(self):
        # In rule_parameters, VPC is set to True and the TagValue of the VPC does match the TagValue of the EC2 => COMPLIANT
        rule_parameters = '{"TagName":"SecurityProfile","VPC":"True","SecurityGroups":"True","ENIs":"True","Subnet":"True","Volumes":"True"}'
        invoking_event = build_invoking_event(tags = {"SecurityProfile":"Medium"})
        ec2_mock()
        response = RULE.lambda_handler(build_lambda_configurationchange_event(rule_parameters=rule_parameters, invoking_event=invoking_event), "")
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'i-08849914c0be5c303'))
        assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################

def build_invoking_event(tags={}):
    invoking_event = {   "configurationItemDiff":"None",
        "configurationItem":{
            "relationships":[
                {
                    "resourceId":"eni-062c55fb309709f82",
                    "resourceName":"None",
                    "resourceType":"AWS::EC2::NetworkInterface",
                    "name":"Contains NetworkInterface"
                
                },
                {
                    "resourceId":"sg-0138abfdacdab11cf",
                    "resourceName":"None",
                    "resourceType":"AWS::EC2::SecurityGroup",
                    "name":"Is associated with SecurityGroup"
                },
                {
                    "resourceId":"subnet-02da297e",
                    "resourceName":"None",
                    "resourceType":"AWS::EC2::Subnet",
                    "name":"Is contained in Subnet"
                },
                {
                    "resourceId":"vol-0f6a865418538b553",
                    "resourceName":"None",
                    "resourceType":"AWS::EC2::Volume",
                    "name":"Is attached to Volume"
                },
                {
                    "resourceId":"vpc-b93de0d3",
                    "resourceName":"None",
                    "resourceType":"AWS::EC2::VPC",
                    "name":"Is contained in Vpc"
                }
            ],
            "tags": tags,
            "configurationItemCaptureTime":"2020-07-14T10:51:29.376Z",
            "configurationItemStatus":"ResourceDiscovered",
            "resourceType":"AWS::EC2::Instance",
            "resourceId":"i-08849914c0be5c303",
        },
        "notificationCreationTime":"2020-07-20T11:14:18.363Z",
        "messageType":"ConfigurationItemChangeNotification",
        "recordVersion":"1.3"
        }
    return json.dumps(invoking_event)

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

def ec2_mock(NetworkInterfaces=[{"Key":"SecurityProfile", "Value":"Medium"}],
             SecurityGroups=[{"Key":"SecurityProfile", "Value":"Medium"}],
             Subnets=[{"Key":"SecurityProfile", "Value":"Medium"}],
             Volumes=[{"Key":"SecurityProfile", "Value":"Medium"}],
             Vpcs=[{"Key":"SecurityProfile", "Value":"Medium"}],
    ):
    describe_network_interfaces_response = {
        "NetworkInterfaces": [{
            "TagSet" : NetworkInterfaces
            }]
        }
    describe_security_groups_response = {
        "SecurityGroups": [{
            "Tags": SecurityGroups
            }]
        }
    describe_subnets_response = {
        "Subnets": [{
            "Tags": Subnets
            }]
        }
    describe_volumes_response = {
        "Volumes": [{
            "Tags": Volumes
            }]
        }
    describe_vpcs_response = {
        "Vpcs": [{
            "Tags": Vpcs
            }]
        }
    EC2_CLIENT_MOCK.reset_mock(return_value=True)
    EC2_CLIENT_MOCK.describe_network_interfaces = MagicMock(return_value=describe_network_interfaces_response)
    EC2_CLIENT_MOCK.describe_security_groups = MagicMock(return_value=describe_security_groups_response)
    EC2_CLIENT_MOCK.describe_subnets = MagicMock(return_value=describe_subnets_response)
    EC2_CLIENT_MOCK.describe_volumes = MagicMock(return_value=describe_volumes_response)
    EC2_CLIENT_MOCK.describe_vpcs = MagicMock(return_value=describe_vpcs_response)