#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure all EC2 Instances that have a certain tag format also have a specific security group
# Description: Checks that all EC2 instances that have a certain tag format also have a specific security group
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance
# Required Parameters: namePattern
# Example Value: ^prod(us|eu|br)[lw]box[0-9]{3}$ (which will match 'produslbox001')
# Required Parameters: securityGroupName
# Example Value: MySecGroup
# 

import boto3
import json
import re

def is_applicable(config_item, event):
    status = config_item['configurationItemStatus']
    event_left_scope = event['eventLeftScope']
    return ((status in ['OK', 'ResourceDiscovered']) and
            (event_left_scope == False) and
            (config_item['resourceType'] == 'AWS::EC2::Instance'))

def evaluate_compliance(config_item, rule_parameters):
    # Initialize evaluation to 'not applicable', i.e. rule doesn't apply
    evaluation = 'NOT_APPLICABLE'
    configuration = config_item['configuration']
    tags = configuration['tags']
    reg = re.compile(rule_parameters['namePattern'])
    # If the config item is for an EC2 instance, then iterate through the tags for that instance
    for tag in tags:
        # Check if this is the 'Name' tag, and that it matches the provided regex value
        if (tag['key'] == 'Name') and (reg.match(tag['value']) != None):
            # if so, initialize to 'non-compliant'
            evaluation = 'NON_COMPLIANT'
            secGroups = configuration['securityGroups']
            # iterate through the security groups and see if the provided secGroup name is in the list. 
            # if so, set compliance to 'compliant'
            for secGroup in secGroups:
                if (secGroup['groupName'] == rule_parameters['securityGroupName']):
                    evaluation = 'COMPLIANT'
    return evaluation

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters'])

    compliance_value = 'NOT_APPLICABLE'

    if is_applicable(invoking_event['configurationItem'], event):
        compliance_value = evaluate_compliance(
                invoking_event['configurationItem'], rule_parameters)

    config = boto3.client('config')
    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
               'ComplianceType': compliance_value,
               'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])


