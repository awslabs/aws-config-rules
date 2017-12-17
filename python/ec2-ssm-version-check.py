################################################################################################################
#                                                                                                                   
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode) 
#                                                                                                                   
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameters: None
#                                                                                                             
# Description: Evaluates all EC2 instances in the region to verify that the latest version of SSM agent is    
# running on the instances.
# The output would be "COMPLIANT" if "The instance is running latest ssm agent version"
# The output would be "NON_COMPLIANT" if "The instance is running and outdated version or SSM agent is not installed                                                                                   
#                                                                                                            
################################################################################################################

import boto3
import json


def evaluate_compliance(instanceid):
    ssmclient = boto3.client('ssm')
    ssmstatus = ssmclient.describe_instance_information(
        InstanceInformationFilterList=[
            {
                'key': 'InstanceIds',
                'valueSet': [str(instanceid)]
            }
        ]
    )
    if ssmstatus['InstanceInformationList']:
        flag = ssmstatus['InstanceInformationList']
        for version in flag:
            if version['IsLatestVersion']:
                return {
                        'compliance_type': "COMPLIANT",
                        'annotation': "The instance is running latest ssm agent version"
                       }
            else:
                return {
                        'compliance_type': "NON_COMPLIANT",
                        'annotation': "The instance is running an outdated ssm agent version"
                       }
    else:
        return {
                'compliance_type': "NON_COMPLIANT",
                'annotation': "SSM agent is not installed"
               }
                   
def evaluation_result(instanceid):
    ec2client = boto3.client('ec2')
    instancedetail = ec2client.describe_instance_status(InstanceIds=[str(instanceid)])
    if instancedetail['InstanceStatuses']:
        response = evaluate_compliance(instanceid)
        return response
    else:
        return {
                'compliance_type' : "NOT_APPLICABLE",
                'annotation' : "Instance is not in running state"
               }


def lambda_handler(event, context):
    print(event)
    invoking_event = json.loads(event['invokingEvent'])
    configclient = boto3.client('config')
    respond = configclient.list_discovered_resources(resourceType='AWS::EC2::Instance')
    print(respond)
    for resource in respond['resourceIdentifiers']:
            instanceid = resource['resourceId']
            evaluationresult = evaluation_result(instanceid) 
            print(instanceid, evaluationresult)
            response = configclient.put_evaluations(
                    Evaluations=[
                        {
                            'ComplianceResourceType': 'AWS::EC2::Instance',
                            'ComplianceResourceId': str(instanceid),
                            'ComplianceType': evaluationresult['compliance_type'],
                            'Annotation': evaluationresult['annotation'],
                            'OrderingTimestamp': invoking_event['notificationCreationTime']
                        },
                    ],
                    ResultToken=event['resultToken'])
            print(response)