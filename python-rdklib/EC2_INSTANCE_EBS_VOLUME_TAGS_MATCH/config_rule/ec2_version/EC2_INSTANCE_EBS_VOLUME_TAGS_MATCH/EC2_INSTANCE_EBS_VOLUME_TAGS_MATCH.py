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

Rule Identifier:
    EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH

Rule Name:
    ec2-instance-ebs-volume-tags-match

Description:
    Checks whether the Amazon Elastic Block Store (EBS) volume includes the Tags from the Amazon Elastic Compute Cloud (Amazon EC2) instance, it's attached to.
    The rule is NON_COMPLIANT if the EBS volume attached to an EC2 instance and missing instance tags.
    The rule is COMPLIANT if the EBS volume attached to an EC2 instance and missing instance tags.

Rationale:
    Ensures that Amazon Elastic Block Store (EBS) volumes are always tagged properly, as the instance it is attached to.

Trigger:
    Configuration change

Reports on:
    AWS::EC2::Volume and AWS::EC2::Instance

Rule Parameters:
    None

Scenarios:
Scenario 1:
     Given: Resource type is AWS::EC2::Instance
       And: EC2 instance does not have an EBS volume attached.
      Then: Return NOT_APPLICABLE

Scenario 2:
     Given: Resource type is AWS::EC2::Volume
       And: EBS volume is not attached to an EC2 instance.
      Then: Return NOT_APPLICABLE

Scenario 3:
     Given: Resource type is AWS::EC2::Instance
       And: EC2 instance and all attached EBS volumes have the same tags attached.
      Then: Return COMPLIANT

Scenario 4:
     Given: Resource type is AWS::EC2::Instance
       And: There are one or more EBS volumes attached to an EC2 instance that do not have the same tags attached.
      Then: Return NON_COMPLIANT

Scenario 5:
     Given: Resource type is AWS::EC2::Volume
       And: EBS volume and the EC2 instance it is attached to have the same tags attached.
      Then: Return COMPLIANT

Scenario 6:
     Given: Resource type is AWS::EC2::Volume
       And: EBS volume and the EC2 instance it is attached to do not have the same tags attached.
      Then: Return NON_COMPLIANT
"""

from time import sleep

from rdklib import ComplianceType, ConfigRule, Evaluation, Evaluator

APPLICABLE_RESOURCES = ["AWS::EC2::Volume", "AWS::EC2::Instance"]
DEFAULT_RESOURCE_TYPE = "AWS::EC2::Volume"

EC2_DESCRIBE_TAGS_PAGE_SIZE = 100
EC2_DESCRIBE_TAGS_THROTTLE_PERIOD = 0.05


class EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        ec2_client = client_factory.build_client("ec2")
        resource_type = configuration_item.get("resourceType")
        if resource_type == "AWS::EC2::Volume":
            # Scenario 2: Volume Resource Type - EBS Volume not attached to an EC2 instance.
            if not configuration_item.get("configuration", {}).get("attachments"):
                return [Evaluation(ComplianceType.NOT_APPLICABLE)]

            volume_id = configuration_item.get("resourceId")
            instance_id = configuration_item.get("configuration").get("attachments")[0].get("instanceId")

            volume_tags = configuration_item.get("configuration", {}).get("tags")
            instance_tags = get_resource_tags(ec2_client, instance_id)
            tags_to_apply = compare_instance_tags_to_volume_tags(instance_tags, volume_tags)

            # Scenario 5: Volume Resource Type - EBS Volume Tags includes same tags as EC2 Instance its attached to.
            if not tags_to_apply:
                return [Evaluation(ComplianceType.COMPLIANT)]

            # Scenario 6: Volume Resource Type - EBS Volume Tags does not include the same tags as EC2 Instance its attached to.
            return [Evaluation(ComplianceType.NON_COMPLIANT)]

        if resource_type == "AWS::EC2::Instance":
            instance_id = configuration_item.get("resourceId")
            instance_tags = configuration_item.get("configuration", {}).get("tags")
            block_device_mappings = configuration_item.get("configuration", {}).get("blockDeviceMappings")

            # Scenario 1: EC2 Resource Type - EC2 Instance has no EBS volumes attached.
            if not block_device_mappings:
                return [Evaluation(ComplianceType.NOT_APPLICABLE)]

            all_volumes = get_volumes_attached_to_instance(block_device_mappings)
            evaluations = []
            for volume_id in all_volumes:
                volume_tags = get_resource_tags(ec2_client, volume_id)
                tags_to_apply = compare_instance_tags_to_volume_tags(instance_tags, volume_tags)

                # Scenario 3: EC2 Resource Type - EBS Volumes attached, includes same tags as EC2 Instance.
                if not tags_to_apply:
                    evaluations.append(Evaluation(ComplianceType.COMPLIANT, volume_id, DEFAULT_RESOURCE_TYPE))

                # Scenario 4: EC2 Resource Type - EBS Volumes attached, does not include same tags as EC2 Instance.
                if tags_to_apply:
                    evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, volume_id, DEFAULT_RESOURCE_TYPE))
            return evaluations
        return []


def get_resource_tags(ec2_client, resource_id):
    ec2_paginator = ec2_client.get_paginator("describe_tags")
    page_iterator = ec2_paginator.paginate(
        Filters=[{"Name": "resource-id", "Values": [resource_id]}], PaginationConfig={"PageSize": EC2_DESCRIBE_TAGS_PAGE_SIZE}
    )
    resource_tags = []
    for page in page_iterator:
        for tag in page["Tags"]:
            # Skip Tag Keys starting with "aws:", as they are reserved for internal AWS use.
            if tag["Key"].startswith("aws:"):
                continue
            tag_value = {"key": tag["Key"], "value": tag["Value"]}
            resource_tags.append(tag_value)
        sleep(EC2_DESCRIBE_TAGS_THROTTLE_PERIOD)
    return resource_tags


def compare_instance_tags_to_volume_tags(instance_tags, volume_tags):
    tags_to_apply = []
    for tag in instance_tags:
        if tag["key"].startswith("aws:"):
            continue
        if tag not in volume_tags:
            tags_to_apply.append(tag)
    return tags_to_apply


def get_volumes_attached_to_instance(block_device_mappings):
    volume_ids = []
    for volume in block_device_mappings:
        volume_id = volume.get("ebs", {}).get("volumeId")
        volume_ids.append(volume_id)
    return volume_ids


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH()
    evaluator = Evaluator(my_rule, APPLICABLE_RESOURCES)
    return evaluator.handle(event, context)
