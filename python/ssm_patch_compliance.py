#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Run SSM patch compliance check against ec2 instances
# Description: Checks ec2 instances are patch compliant via SSM against SSM patch baseline.
#
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameter name: PoliciesToCheck
# Required Parameter value example: Name bastion (Tag key and value for EC2 instances). It will find all instances with that particular
# tag and for each instance it will insert a compliant/non compliant evaluation into AWS config.
# IAM role running this lambda should be able to call ec2:describe , ssm:list_compliance_items and config:putEvaluations

import json
import boto3




APPLICABLE_RESOURCES = ["AWS::EC2::Instance"]


def validate_patch_baseline(instanceid):
    client = boto3.client('ssm')
    filters = [
		{'Key':'ComplianceType','Values':['Patch'],'Type':'EQUAL'},
		{'Key':'Status','Values':['NON_COMPLIANT'],'Type':'EQUAL'}
	     ]
    response = client.list_compliance_items(Filters=filters,ResourceIds=[instanceid],ResourceTypes=['ManagedInstance'])
    print(response)
    if len(response['ComplianceItems']) > 0:
        #link_to_ssm = '<a href="https://console.aws.amazon.com/systems-manager/managed-instances/' + instanceid + '/configurationCompliance>"'
        security_critical = ''
        
        for item in response['ComplianceItems']:
            
            if 'Classification' in item['Details']:
                if item['Details']['Classification'] == 'Security':
                    #security_critical = security_critical + item['Title'] + ":"
                    security_critical = " Several pending security patches."
        violation="NON_COMPLIANT: " + instanceid  + ":" + security_critical
        print(violation)
        return violation

    response = client.describe_instance_patch_states(InstanceIds=[instanceid])
    
    if len(response['InstancePatchStates']) == 0:
        violation = 'NON_MANAGED'
        return violation
    
    
    return None


def evaluate_compliance(configuration_item,instanceid):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }


    if configuration_item['configurationItemStatus'] == "ResourceDeleted":
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The configurationItem was deleted " +
                          "and therefore cannot be validated"
        }


    violation = validate_patch_baseline(instanceid)

    if violation == 'NON_MANAGED':
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : instanceid + " is not managed by SSM"
        }

    if violation:
            return {
                "compliance_type": "NON_COMPLIANT",
                "annotation": violation
            }

    return {
        "compliance_type": "COMPLIANT",
        "annotation": "This resource is compliant with the rule."
    }



def lambda_handler(event, context):

    print(event)
    invoking_event = json.loads(event["invokingEvent"])
    #configuration_item = invoking_event["configurationItem"]
    configuration_item = {'resourceType':'AWS::EC2::Instance'}
    rule_parameters = json.loads(event["ruleParameters"])
    

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    #Loop through rule parameters and call evaluate compliance for each instance 
    #with matching tag. 
    
   
    for key,val in rule_parameters.items():
        filter = [{'Name': 'tag:' + key, 'Values': [val]}]
        print(filter)
        
    ec2 = boto3.resource('ec2')
    
    for instance in ec2.instances.filter(Filters=filter):
        instanceid = instance.id
        configuration_item["resourceId"] = instanceid
        configuration_item['configurationItemStatus'] = "OK"
        evaluation = evaluate_compliance(configuration_item,instanceid)
        
        print(evaluation)

        config = boto3.client("config")
        config.put_evaluations(
            Evaluations=[
                {
                    "ComplianceResourceType":
                        configuration_item["resourceType"],
                    "ComplianceResourceId":
                        configuration_item["resourceId"],
                    "ComplianceType":
                        evaluation["compliance_type"],
                    "Annotation":
                        evaluation["annotation"],
                    "OrderingTimestamp":
                        invoking_event['notificationCreationTime']
                },
            ],
            ResultToken=result_token
        )

