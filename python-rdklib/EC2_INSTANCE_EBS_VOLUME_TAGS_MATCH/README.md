# EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH

- [EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH](#ec2_instance_ebs_volume_tags_match)
  - [Description](#description)
  - [Config Rule Info](#config-rule-info)
  - [Config Rule Versions (RDKlib)](#config-rule-versions-rdklib)
  - [SSM Automation Document](#ssm-automation-document)

## Description

This solution provides 2 different versions of the same custom AWS Config Rule that was developed using
[RDKlib](https://github.com/awslabs/aws-config-rdklib), and an AWS Systems Manager (SSM) Automation document to remediate the given AWS Config rules.

## Config Rule Info

**Description:** Checks whether the Amazon Elastic Block Store (EBS) volume includes the Tags from the Amazon Elastic Compute Cloud (Amazon EC2)
instance, it's attached to.

- The rule is `NON_COMPLIANT` if the EBS volume attached to an EC2 instance and missing instance tags.
- The rule is `COMPLIANT` if the EBS volume attached to an EC2 instance and missing instance tags.

**Rationale:** Ensures that Amazon Elastic Block Store (EBS) volumes are always tagged properly, as the instance it is attached to.

## Config Rule Versions (RDKlib)

1. The [ec2-version](config_rule/ec2_version/EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH) Config rule uses the
   [DescribeTags](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeTags.html) API to identify the tags on the resource.
2. The [config-version](config_rule/config-version/EC2_INSTANCE_EBS_VOLUME_TAGS_MATCH) Config rule uses the
   [SelectResourceConfig](https://docs.aws.amazon.com/config/latest/APIReference/API_SelectResourceConfig.html) API to perform a SQL query to AWS
   Config to identify the tags on the resource.

## SSM Automation Document

This [EC2-Tag-Volumes](ssm_automation/ec2_tag_volumes_ssm_document_executeScript.yaml) document tags Amazon EBS volumes to ensure it includes the same
Tags as those of the EC2 Instance its attached to. This document uses the below APIs:

- [DescribeVolumes](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVolumes.html)
- [DescribeTags](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeTags.html)
- [CreateTags](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTags.html)
