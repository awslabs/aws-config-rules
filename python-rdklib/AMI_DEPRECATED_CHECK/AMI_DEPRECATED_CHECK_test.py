#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#

import unittest
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError
import rdklib
from rdklib import Evaluation, ComplianceType
from rdklibtest import assert_successful_evaluation

#############
# Main Code #
#############

MODULE = __import__('AMI_DEPRECATED_CHECK')
RULE = MODULE.AMI_DEPRECATED_CHECK()

#example for mocking S3 API calls
CLIENT_FACTORY = MagicMock()
EC2_CLIENT_MOCK = MagicMock()
ASG_CLIENT_MOCK = MagicMock()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == "ec2":
        return EC2_CLIENT_MOCK
    elif client_name == 'autoscaling':
        return ASG_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")


def mock_evaluator_handle(event, context):
    return f"Event: {event} - Context: {context}"


@patch.object(CLIENT_FACTORY, "build_client", MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    deprecated_ami_response = {
        "Images": [
            {
                "CreationDate": "2021-07-19T19:03:00.000Z",
                "ImageId": "ami-abcd1234",
                "Name": "test-image",
                "DeprecationTime": "2021-07-21T17:03:00.000Z"
            }
        ]
    }

    compliant_ami_response = {
        "Images": [
            {
                "CreationDate": "2021-07-01T19:03:00.000Z",
                "ImageId": "ami-abcd1234",
                "Name": "test-image"
            }
        ]
    }

    missing_ami_response = {'Images': []}

    instance_response = {
        "Reservations": [
            {
                "Groups": [],
                "Instances": [
                    {
                        "ImageId": "ami-abcd1234",
                        "InstanceId": "i-abcd1234"
                    }
                ]
            }
        ]
    }

    asg_launch_template = {
        "AutoScalingGroups": [
            {
                "AutoScalingGroupName": "test-asg",
                "LaunchTemplate": {
                    "LaunchTemplateId": "lt-xyz789",
                    "LaunchTemplateName": "test-lt",
                    "Version": "1"
                }
            }
        ]
    }

    asg_mixed_instances = {
        "AutoScalingGroups": [
            {
                "AutoScalingGroupName": "test-asg",
                "MixedInstancesPolicy": {
                    "LaunchTemplate": {
                        "LaunchTemplateSpecification": {
                            "LaunchTemplateId": "lt-xyz789",
                            "LaunchTemplateName": "test-lt",
                            "Version": 1
                        }
                    }
                }
            }
        ]
    }

    asg_launch_config = {
        "AutoScalingGroups": [
            {
                "AutoScalingGroupName": "test-asg",
                "LaunchConfigurationName": "test-lc"
            }
        ]
    }

    launch_template_versions = {
        'LaunchTemplateVersions': [
            {
                'LaunchTemplateData': {
                    'ImageId': 'ami-6057e21a'
                },
                'LaunchTemplateId': "lt-xyz789",
                'LaunchTemplateName': "test-lt",
                'VersionNumber': 2,
            }
        ]
    }

    launch_config = {
        "LaunchConfigurations": [
            {
                "LaunchConfigurationName": "test-lc",
                "ImageId": "ami-abcd1234"
            }
        ]
    }

    def setUp(self):
        EC2_CLIENT_MOCK.reset_mock()
        ASG_CLIENT_MOCK.reset_mock()

    def test_evaluate_compliant_instance(self):
        EC2_CLIENT_MOCK.describe_instances.return_value = self.instance_response
        EC2_CLIENT_MOCK.describe_images.return_value = self.compliant_ami_response
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {'mode': 'EC2'})
        instance = self.instance_response['Reservations'][0]['Instances'][0]
        response_expected = [Evaluation(
            complianceType=ComplianceType.COMPLIANT,
            resourceId=instance['InstanceId'],
            resourceType='AWS::EC2::Instance',
            annotation=f'Image {instance["ImageId"]} is not deprecated'
        )]
        assert_successful_evaluation(self, response, response_expected)

    def test_evaluate_noncompliant_instance_deprecated_ami(self):
        EC2_CLIENT_MOCK.describe_instances.return_value = self.instance_response
        EC2_CLIENT_MOCK.describe_images.return_value = self.deprecated_ami_response
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {'mode': 'EC2'})
        instance = self.instance_response['Reservations'][0]['Instances'][0]
        response_expected = [Evaluation(
            complianceType=ComplianceType.NON_COMPLIANT,
            resourceId=instance['InstanceId'],
            resourceType='AWS::EC2::Instance',
            annotation=f'Image {instance["ImageId"]} is deprecated'
        )]
        assert_successful_evaluation(self, response, response_expected)

    def test_evaluate_noncompliant_instance_missing_ami(self):
        EC2_CLIENT_MOCK.describe_instances.return_value = self.instance_response
        EC2_CLIENT_MOCK.describe_images.return_value = self.missing_ami_response
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {'mode': 'EC2'})
        instance = self.instance_response['Reservations'][0]['Instances'][0]
        response_expected = [Evaluation(
            complianceType=ComplianceType.NON_COMPLIANT,
            resourceId=instance['InstanceId'],
            resourceType='AWS::EC2::Instance',
            annotation=f'Error checking {instance["ImageId"]}, assuming noncompliant'
        )]
        assert_successful_evaluation(self, response, response_expected)

    def test_evaluate_asg_mixed_instances_launch_template_compliant(self):
        ASG_CLIENT_MOCK.describe_auto_scaling_groups.return_value = self.asg_mixed_instances
        EC2_CLIENT_MOCK.describe_launch_template_versions.return_value = self.launch_template_versions
        EC2_CLIENT_MOCK.describe_images.return_value = self.compliant_ami_response
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {'mode': 'ASG'})
        asg = self.asg_mixed_instances['AutoScalingGroups'][0]
        launch_template_version = self.launch_template_versions['LaunchTemplateVersions'][0]
        response_expected = [Evaluation(
            complianceType=ComplianceType.COMPLIANT,
            resourceId=asg['AutoScalingGroupName'],
            resourceType='AWS::AutoScaling::AutoScalingGroup',
            annotation=f'Image {launch_template_version["LaunchTemplateData"]["ImageId"]} is not deprecated'
        )]
        assert_successful_evaluation(self, response, response_expected)

    def test_evaluate_noncompliant_asg_launch_config_deprecated_ami(self):
        ASG_CLIENT_MOCK.describe_auto_scaling_groups.return_value = self.asg_launch_config
        ASG_CLIENT_MOCK.describe_launch_configurations.return_value = self.launch_config
        EC2_CLIENT_MOCK.describe_images.return_value = self.deprecated_ami_response
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {'mode': 'ASG'})
        asg = self.asg_launch_config['AutoScalingGroups'][0]
        launch_config = self.launch_config['LaunchConfigurations'][0]
        response_expected = [Evaluation(
            complianceType=ComplianceType.NON_COMPLIANT,
            resourceId=asg['AutoScalingGroupName'],
            resourceType='AWS::AutoScaling::AutoScalingGroup',
            annotation=f'Image {launch_config["ImageId"]} is deprecated'
        )]
        assert_successful_evaluation(self, response, response_expected)

    def test_evaluate_noncompliant_asg_launch_template_missing_ami(self):
        ASG_CLIENT_MOCK.describe_auto_scaling_groups.return_value = self.asg_launch_template
        ASG_CLIENT_MOCK.describe_launch_template_versions.return_value = self.launch_template_versions
        EC2_CLIENT_MOCK.describe_images.return_value = self.missing_ami_response
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {'mode': 'ASG'})
        asg = self.asg_launch_template['AutoScalingGroups'][0]
        launch_template_version = self.launch_template_versions['LaunchTemplateVersions'][0]
        response_expected = [Evaluation(
            complianceType=ComplianceType.NON_COMPLIANT,
            resourceId=asg['AutoScalingGroupName'],
            resourceType='AWS::AutoScaling::AutoScalingGroup',
            annotation=f'Error checking {launch_template_version["LaunchTemplateData"]["ImageId"]}, assuming noncompliant'
        )]
        assert_successful_evaluation(self, response, response_expected)

if __name__ == '__main__':
    unittest.main()
