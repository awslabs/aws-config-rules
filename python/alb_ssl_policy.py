#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  alb_ssl_policy_check
Description:
  Checks that listener of Application Load Balancer has configured applicable SSL policy.
Trigger:
  Configuration change
Resource Type to report on:
  AWS::LoadBalancingV2::LoadBalancer
Rule Parameters:
  | ---------------------- | --------- | -------------------------------------------------------------------------------------- |
  | Parameter Name         | Type      | Description                                                                            |
  | ---------------------- | --------- | -------------------------------------------------------------------------------------- |
  | alb_arn                | Optional  | The ALB arname where the trail is logging.                                             |
  | ---------------------- | --------- | -------------------------------------------------------------------------------------- |
  | alb_client             | Optional  | The ALB cliet which get from get_client() function                                     |
  | ---------------------- | --------- | -------------------------------------------------------------------------------------- |
  | listeners              | Optional  | The list of listerner which get using ALB arn                                          |
  | ---------------------- | --------- | -------------------------------------------------------------------------------------- |
  | COMPLIANT_POLICY       | Constant  | The list of ssl policy name which check whether lister configred                       |
  | ---------------------- | --------- | -------------------------------------------------------------------------------------- |
Feature:
  In order to: apply ssl policy to listers
  As: a Security Officer
  I want: to chaging configuration of applicatio loac balancer.
Scenarios:
  Scenario 1:
    Given: SslPolicy is in COMPLIANT_POLICY 
     Then: Return COMPLIANT
  Scenario 2:
    Given: SslPolicy is not in COMPLIANT_POLICY
     THEN: RETURN NON_COMPLIANT
'''
import json
import datetime
import boto3
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = ['AWS::LoadBalancingV2::LoadBalancer']
# Pre defined policy name
COMPLIANT_POLICY = ['ELBSecurityPolicy-2016-08','ELBSecurityPolicy-FS-2018-06']

##############
# Functions  #
##############

def evaluate_compliance(event, configuration_item, valid_rule_parameters):
	alb_arn = configuration_item['arn']
	alb_client = get_client('elbv2',event);

	listeners = alb_client.describe_listeners( LoadBalancerArns = [alb_arn,], )

	for l in listeners['Listeners']:
		if ( 'SslPolicy' in l.keys()):
			if(l['SslPolicy'] not in COMPLIANT_POLICY):
				return 'NON_COMPLIANT'

	return 'COMPLIANT'
			
def get_client(service, event):
    """Return the service boto client. It should be used instead of directly calling the client.

    Keyword arguments:
    service -- the service name used for calling the boto.client()
    event -- the event variable given in the lambda handler
    """
    if not ASSUME_ROLE_MODE:
        return boto3.client(service)
    credentials = get_assume_role_credentials(event["executionRoleArn"])
    return boto3.client(service, aws_access_key_id=credentials['AccessKeyId'],
                        aws_secret_access_key=credentials['SecretAccessKey'],
                        aws_session_token=credentials['SessionToken']
                       )

