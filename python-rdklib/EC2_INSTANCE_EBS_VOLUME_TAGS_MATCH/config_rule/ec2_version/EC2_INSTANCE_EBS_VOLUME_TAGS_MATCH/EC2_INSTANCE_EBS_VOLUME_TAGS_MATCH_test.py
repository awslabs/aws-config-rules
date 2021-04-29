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
import unittest
from unittest.mock import MagicMock, patch

from rdklib import ComplianceType, Evaluation
from rdklibtest import assert_successful_evaluation

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = "AWS::EC2::Volume"

#############
# Main Code #
#############

MODULE = __import__("EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH")
RULE = MODULE.EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH()

CLIENT_FACTORY = MagicMock()
EC2_CLIENT_MOCK = MagicMock()
EC2_PAGINATOR_MOCK = MagicMock()


def mock_get_client(client_name, *args, **kwargs):
    if client_name == "ec2":
        return EC2_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")


def mock_evaluator_handle(event, context):
    return f"Event: {event} - Context: {context}"


@patch.object(CLIENT_FACTORY, "build_client", MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    ci_wrong_resource_type = {"resourceType": "AWS::EC2::WRONG"}
    # AWS::EC2::Volume - Configuration Items
    ci_ebs_volume_not_attached = {"resourceType": "AWS::EC2::Volume", "configuration": {"attachments": []}}
    ci_ebs_volume_attached_with_tags1 = {
        "resourceType": "AWS::EC2::Volume",
        "resourceId": "vol-123abc",
        "configuration": {
            "attachments": [{"instanceId": "i-123abc", "volumeId": "vol-123abc"}],
            "tags": [
                {"key": "tag1", "value": "item1"},
                {"key": "tag2", "value": "item2"},
                {"key": "aws:test1", "value": "awsskip"},
                {"key": "tag3", "value": "exclusive2volume"},
            ],
        },
    }
    ci_ebs_volume_attached_with_tags2 = {
        "resourceType": "AWS::EC2::Volume",
        "resourceId": "vol-123abc",
        "configuration": {
            "attachments": [{"instanceId": "i-123abc", "volumeId": "vol-123abc"}],
            "tags": [
                {"key": "tag1", "value": "item55"},
                {"key": "tag2", "value": "item77"},
                {"key": "aws:test2", "value": "awsskip"},
                {"key": "tag3", "value": "exclusive2volume"},
            ],
        },
    }
    # AWS::EC2::Instance - Configuration Items
    ci_ec2_instance_no_ebs_volumes_attached = {
        "resourceType": "AWS::EC2::Instance",
        "resourceId": "i-123abc",
        "configuration": {"blockDeviceMappings": []},
    }
    ci_ec2_instance_with_tags1 = {
        "resourceType": "AWS::EC2::Instance",
        "resourceId": "i-123abc",
        "configuration": {
            "blockDeviceMappings": [{"ebs": {"volumeId": "vol-123abc"}}],
            "tags": [
                {"key": "tag1", "value": "item1"},
                {"key": "tag2", "value": "item2"},
                {"key": "aws:test1", "value": "awsskip"},
            ],
        },
    }
    ci_ec2_instance_with_tags2 = {
        "resourceType": "AWS::EC2::Instance",
        "resourceId": "i-123abc",
        "configuration": {
            "blockDeviceMappings": [{"ebs": {"volumeId": "vol-123abc"}}],
            "tags": [
                {"key": "tag1", "value": "item55"},
                {"key": "tag2", "value": "item77"},
                {"key": "aws:test2", "value": "awsskip"},
            ],
        },
    }
    ebs_volume_tags2 = [
        {
            "Tags": [
                {"Key": "tag1", "Value": "item55"},
                {"Key": "tag2", "Value": "item77"},
                {"Key": "aws:test2", "Value": "awsskip"},
                {"Key": "tag3", "Value": "exclusive2volume"},
            ]
        }
    ]
    ec2_instance_tags2 = [
        {
            "Tags": [
                {"Key": "tag1", "Value": "item55"},
                {"Key": "tag2", "Value": "item77"},
                {"Key": "aws:test2", "Value": "awsskip"},
            ]
        }
    ]

    def setUp(self):
        EC2_CLIENT_MOCK.reset_mock()

    # Scenario - Returns Empty if Resource Type is received
    def test_scenario_evaluatechange_wrong_resource_type_returnsempty(self):
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_wrong_resource_type, {})
        response_expected = []
        self.assertEqual(response, response_expected)

    # Scenario 1: EC2 Resource Type - EC2 Instance has no EBS volumes attached.
    def test_scenario1_evaluatechange_ec2_instance_no_ebs_volumes_attached_returnsnotapplicable(self):
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_ec2_instance_no_ebs_volumes_attached, {})
        response_expected = [Evaluation(ComplianceType.NOT_APPLICABLE)]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 2: Volume Resource Type - EBS Volume not attached to an EC2 instance.
    def test_scenario2_evaluatechange_ebs_volume_not_attached_returnsnotapplicable(self):
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_ebs_volume_not_attached, {})
        response_expected = [Evaluation(ComplianceType.NOT_APPLICABLE)]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 3: EC2 Resource Type - EBS Volumes attached, includes same tags as EC2 Instance.
    def test_scenario3_evaluatechange_ec2_instance_volumes_has_tags_from_ec2_instance_returnscompliant(self):
        EC2_CLIENT_MOCK.get_paginator.return_value = EC2_PAGINATOR_MOCK
        EC2_PAGINATOR_MOCK.paginate.return_value = self.ebs_volume_tags2
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_ec2_instance_with_tags2, {})
        response_expected = [Evaluation(ComplianceType.COMPLIANT, "vol-123abc", RESOURCE_TYPE)]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 4: EC2 Resource Type - EBS Volumes attached, does not include same tags as EC2 Instance.
    def test_scenario4_evaluatechange_ec2_instance_volumes_missing_tags_from_ec2_instance_returnsnoncompliant(self):
        EC2_CLIENT_MOCK.get_paginator.return_value = EC2_PAGINATOR_MOCK
        EC2_PAGINATOR_MOCK.paginate.return_value = self.ebs_volume_tags2
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_ec2_instance_with_tags1, {})
        response_expected = [Evaluation(ComplianceType.NON_COMPLIANT, "vol-123abc", RESOURCE_TYPE)]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 5: Volume Resource Type - EBS Volume Tags includes same tags as EC2 Instance its attached to.
    def test_scenario5_evaluatechange_ebs_volume_attached_has_tags_from_ec2_instance_returnscompliant(self):
        EC2_CLIENT_MOCK.get_paginator.return_value = EC2_PAGINATOR_MOCK
        EC2_PAGINATOR_MOCK.paginate.return_value = self.ec2_instance_tags2
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_ebs_volume_attached_with_tags2, {})
        response_expected = [Evaluation(ComplianceType.COMPLIANT)]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 6: Volume Resource Type - EBS Volume Tags does not include the same tags as EC2 Instance its attached to.
    def test_scenario6_evaluatechange_ebs_volume_attached_missing_tags_from_ec2_instance_returnsnoncompliant(self):
        EC2_CLIENT_MOCK.get_paginator.return_value = EC2_PAGINATOR_MOCK
        EC2_PAGINATOR_MOCK.paginate.return_value = self.ec2_instance_tags2
        response = RULE.evaluate_change({}, CLIENT_FACTORY, self.ci_ebs_volume_attached_with_tags1, {})
        response_expected = [Evaluation(ComplianceType.NON_COMPLIANT)]
        assert_successful_evaluation(self, response, response_expected)

    # No scenario lambda handler passed an event and context
    @patch.object(MODULE.Evaluator, "handle", side_effect=mock_evaluator_handle)
    def test_lambda_handler_called_with_event_and_context(self, mock_evaluator):
        response = MODULE.lambda_handler("event", "context")
        response_expected = "Event: event - Context: context"
        self.assertEqual(response, response_expected)
