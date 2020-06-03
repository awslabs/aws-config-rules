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
"""
#####################################
##           Gherkin               ##
#####################################

Rule Name:
  EC2_TAG_VOLUMES

Description:
  Checks whether the Amazon Elastic Block Store (EBS) volume includes the Tags from the Amazon Elastic Compute Cloud (Amazon EC2) instance, it's attached to.  The rule is NON_COMPLIANT if the volume is attached to an instance and doesn't include the instance tags. # noqa: E501

Rationale:
  Ensures that Amazon Elastic Block Store (EBS) volumes are always tagged properly, as the instance it is attached to.

Trigger:
  Configuration Change on AWS::EC2::Volume

Reports on:
  AWS::IAM::Volume

Rule Parameters:
  ExecutionRoleName
    (Required) AWS Identity and Access Management (IAM) role that will be assumed by the Custom Config Rule Lambda.

Scenarios:
  Scenario 1:
    Given: The EBS Volume Tags includes all of the Tags associated to the EC2 instance that it is attached to.
     Then: return COMPLIANT
  Scenario 2:
    Given: The EBS Volume Tags does not include all of the Tags associated to the EC2 instance that it is attached to.
     Then: return NON_COMPLIANT
  Scenario 3:
    Given: The EBS Volume is not attached to an EC2 instance.
     Then: return NOT_APPLICABLE
"""

from rdklib import ComplianceType, ConfigRule, Evaluation, Evaluator

APPLICABLE_RESOURCES = ["AWS::EC2::Volume", "AWS::EC2::Instance"]
DEFAULT_RESOURCE_TYPE = "AWS::EC2::Volume"


class EC2_TAG_VOLUMES(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        ec2_client = client_factory.build_client("ec2")
        resource_type = configuration_item.get("resourceType")
        if resource_type == "AWS::EC2::Volume":
            volume_id = configuration_item.get("resourceId")
            if configuration_item.get("configuration").get("attachments"):
                instance_id = configuration_item.get("configuration").get("attachments")[0].get("instanceId")
            # Scenario:3 EBS Volume not attached to an EC2 instance.
            if not configuration_item.get("configuration").get("attachments"):
                return [Evaluation(ComplianceType.NOT_APPLICABLE)]
            volume_tags = configuration_item.get("configuration").get("tags")
            instance_tags = get_instance_tags(ec2_client, instance_id)
            tags_to_apply = compare_instance_tags_to_volume_tags(instance_tags, volume_tags)
            # Scenario:1 EBS Volume Tags includes same tags as EC2 Instance its attached to.
            if not tags_to_apply:
                return [Evaluation(ComplianceType.COMPLIANT)]
            # Scenario:2 EBS Volume Tags does not include the same tags as EC2 Instance its attached to.
            annotation = "EBS Volume needs to have EC2 Instance Tags applied."
            return [Evaluation(ComplianceType.NON_COMPLIANT, annotation=annotation)]

        if resource_type == "AWS::EC2::Instance":
            instance_id = configuration_item.get("resourceId")
            instance_tags = configuration_item.get("configuration").get("tags")
            block_device_mappings = configuration_item.get("configuration").get("blockDeviceMappings")
            all_volumes = get_volumes_attached_to_instance(block_device_mappings)
            evaluations = list()
            for volume in all_volumes:
                volume_id = volume
                volume_tags = get_volume_tags(ec2_client, volume_id)
                tags_to_apply = compare_instance_tags_to_volume_tags(instance_tags, volume_tags)
                # Scenario:1 EBS Volume Tags includes same tags as EC2 Instance its attached to.
                if not tags_to_apply:
                    evaluations.append(Evaluation(ComplianceType.COMPLIANT, volume_id, DEFAULT_RESOURCE_TYPE))
                # Scenario:2 EBS Volume Tags does not include the same tags as EC2 Instance its attached to.
                if tags_to_apply:
                    annotation = "EBS Volume needs to have EC2 Instance Tags applied."
                    evaluations.append(
                        Evaluation(ComplianceType.NON_COMPLIANT, volume_id, DEFAULT_RESOURCE_TYPE, annotation)
                    )
            return evaluations

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = rule_parameters
        return valid_rule_parameters


def get_volume_tags(ec2_client, volume_id):
    response = ec2_client.describe_tags(Filters=[{"Name": "resource-id", "Values": [volume_id]}])
    volume_tags = list()
    for tag in response.get("Tags"):
        # Skip Tag Keys starting with "aws:", as they are reserved for internal AWS use.
        if tag["Key"].startswith("aws:"):
            continue
        tag_value = {"Key": tag["Key"], "Value": tag["Value"]}
        volume_tags.append(tag_value)
    return volume_tags


def get_instance_tags(ec2_client, instance_id):
    response = ec2_client.describe_tags(Filters=[{"Name": "resource-id", "Values": [instance_id]}])
    instance_tags = list()
    for tag in response.get("Tags"):
        # Skip Tag Keys starting with "aws:", as they are reserved for internal AWS use.
        if tag["Key"].startswith("aws:"):
            continue
        tag_value = {"Key": tag["Key"], "Value": tag["Value"]}
        instance_tags.append(tag_value)
    return instance_tags


def compare_instance_tags_to_volume_tags(instance_tags, volume_tags):
    tags_to_apply = [i for i in instance_tags if i not in volume_tags]
    return tags_to_apply


def get_volumes_attached_to_instance(block_device_mappings):
    volume_ids = list()
    for volume in block_device_mappings:
        volume_id = volume.get("ebs").get("volumeId")
        volume_ids.append(volume_id)

    return volume_ids


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = EC2_TAG_VOLUMES()
    evaluator = Evaluator(my_rule, APPLICABLE_RESOURCES)
    return evaluator.handle(event, context)
