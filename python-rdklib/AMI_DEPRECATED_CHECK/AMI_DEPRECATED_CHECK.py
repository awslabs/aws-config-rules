#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#

from datetime import datetime
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

APPLICABLE_RESOURCES = ["AWS::AutoScaling::AutoScalingGroup", "AWS::EC2::Instance"]
DEFAULT_RESOURCE_TYPE = "AWS::EC2::Instance"

class AMI_DEPRECATED_CHECK(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        pass

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        ec2_client = client_factory.build_client("ec2")
        asg_client = client_factory.build_client("autoscaling")

        mode = valid_rule_parameters['mode']
        if mode == 'ASG':
            return self.evaluate_asgs(ec2_client, asg_client)
        return self.evaluate_instances(ec2_client)

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = rule_parameters
        if 'mode' not in rule_parameters:
            valid_rule_parameters['mode'] = 'EC2'
        if valid_rule_parameters['mode'] not in ('EC2', 'ASG'):
            raise ValueError('Rule only supports parameter mode of EC2 and ASG')
        return valid_rule_parameters

    def evaluate_instances(self, ec2_client):
        evaluations = []
        instances = get_all_instances(ec2_client)
        for instance in instances:
            ami_id = instance['ImageId']

            compliance_type, annotation = self.evaluate_ami(ec2_client, ami_id)
            evaluation = Evaluation(
                resourceType='AWS::EC2::Instance',
                resourceId=instance['InstanceId'],
                complianceType=compliance_type,
                annotation=annotation,
            )
            evaluations.append(evaluation)

        return evaluations

    def evaluate_asgs(self, ec2_client, asg_client):
        evaluations = []
        asgs = get_all_asgs(asg_client)
        for asg in asgs:
            ami_id = get_ami_from_asg(asg_client, ec2_client, asg)

            compliance_type, annotation = self.evaluate_ami(ec2_client, ami_id)
            evaluation = Evaluation(
                resourceType='AWS::AutoScaling::AutoScalingGroup',
                resourceId=asg['AutoScalingGroupName'],
                complianceType=compliance_type,
                annotation=annotation,
            )
            evaluations.append(evaluation)

        return evaluations

    def evaluate_ami(self, ec2_client, ami_id):
        if not ami_id:
            print(f'AMI {ami_id} is None, assuming deprecated/unshared/deleted')
            return ComplianceType.NON_COMPLIANT, f'Image {ami_id} is either unshared or deleted'
        try:
            response = ec2_client.describe_images(
                ImageIds=[ami_id],
                IncludeDeprecated=True,
            )
            image = response['Images'][0]
            if 'DeprecationTime' not in image:
                return ComplianceType.COMPLIANT, f'Image {ami_id} is not deprecated'
            deprecation_time = datetime.strptime(image['DeprecationTime'], '%Y-%m-%dT%H:%M:%S.%fZ')
            current_time = datetime.utcnow()
            if deprecation_time < current_time:
                return ComplianceType.NON_COMPLIANT, f'Image {ami_id} is deprecated'
            return ComplianceType.COMPLIANT, f'Image {ami_id} is not deprecated'
        except Exception as e:
            print(f'Exception checking {ami_id}, assuming deprecated/unshared/deleted: {e}')
            return ComplianceType.NON_COMPLIANT, f'Error checking {ami_id}, assuming noncompliant'


def get_ami_from_asg(asg_client, ec2_client, asg):
    # asg is the individual asg metadata from the AWS API
    try:
        if 'MixedInstancesPolicy' in asg:
            launch_template_spec = asg['MixedInstancesPolicy']['LaunchTemplate'] \
                ['LaunchTemplateSpecification']
            response = ec2_client.describe_launch_template_versions(
                LaunchTemplateId = launch_template_spec['LaunchTemplateId'],
                Versions = [launch_template_spec['Version']]
            )
            return response['LaunchTemplateVersions'][0]['LaunchTemplateData']['ImageId']
        elif 'LaunchTemplate' in asg:
            launch_template_spec = asg['LaunchTemplate']
            response = ec2_client.describe_launch_template_versions(
                LaunchTemplateId = launch_template_spec['LaunchTemplateId'],
                Versions = [launch_template_spec['Version']]
            )
            return response['LaunchTemplateVersions'][0]['LaunchTemplateData']['ImageId']
        else:
            launch_config_name = asg['LaunchConfigurationName']
            response = asg_client.describe_launch_configurations(
                LaunchConfigurationNames = [launch_config_name]
            )
            return response['LaunchConfigurations'][0]['ImageId']
    except Exception as e:
        asg_name = asg.get('AutoScalingGroupName', 'Unknown')
        print(f'Error retrieving AMI from ASG {asg_name}: {e}')
        return None

def get_all_asgs(asg_client):
    asgs = []
    response = asg_client.describe_auto_scaling_groups()
    asgs.extend(response['AutoScalingGroups'])
    while 'NextToken' in response:
        response = asg_client.describe_auto_scaling_groups(response['NextToken'])
        asgs.extend(response['AutoScalingGroups'])
    return asgs

def get_all_instances(ec2_client):
    instances = []
    # Get all instances with pagination
    response = ec2_client.describe_instances(
        Filters=[
            {
                'Name': 'instance-state-name',
                'Values': ['pending', 'running', 'stopping', 'stopped']
            },
        ],
    )
    for reservation in response["Reservations"]:
        instances.extend(reservation["Instances"])
    while 'NextToken' in response:
        response = ec2_client.describe_instances(NextToken=response['NextToken'])
        for reservation in response["Reservations"]:
            instances.extend(reservation["Instances"])
    return instances


################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = AMI_DEPRECATED_CHECK()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
