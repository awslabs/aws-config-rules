################################################################################################################
#                                                                                                                   
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode) 
#                                                                                                                   
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameters: None
#                                                                                                             
# Description: Evaluates all Customer managed CMKs to verify if annual rotation is enabled.
# The output would be "COMPLIANT" if annual rotation is enabled
# The output would be "NON_COMPLIANT" if annual rotation is enabled                                                                                   
# 
# Your Lambda function execution role will need to have a policy that provides the appropriate
# permissions.  Here is a policy that you can consider.  You should validate this for your own
# environment                      
#{
#    "Version": "2012-10-17",
#    "Statement": [
#        {
#            "Effect": "Allow",
#           "Action": [
#                "logs:CreateLogGroup",
#                "logs:CreateLogStream",
#                "logs:PutLogEvents"
#            ],
#            "Resource": "arn:aws:logs:*:*:*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "config:Put*",
#                "config:Get*",
#                "config:List*",
#                "config:Describe*",
#                "kms:ListKeys",
#                "kms:DescribeKey",
#                "kms:GetKeyRotationStatus",
#            ],
#            "Resource": "*"
#        }
#    ]
#}                                                                                     
################################################################################################################

import boto3
import json

def lambda_handler (event, context):
    invoking_event = json.loads(event['invokingEvent'])
    kmsclient = boto3.client('kms')
    response = kmsclient.list_keys()
    keys = response['Keys']
    for key in keys:
        keyid = key['KeyId']
        customercmk = kmsclient.describe_key(KeyId = keyid)
        if customercmk['KeyMetadata']['KeyState'] == "Enabled" and customercmk['KeyMetadata']['Origin'] == "AWS_KMS" and customercmk['KeyMetadata']['KeyManager'] == "CUSTOMER":
            rotationstatus = kmsclient.get_key_rotation_status(KeyId = keyid)
            if rotationstatus['KeyRotationEnabled']:
                compliance_type = "COMPLIANT"
                annotation = "Annual rotation is enabled"
            else:
                compliance_type = "NON_COMPLIANT"
                annotation = "Annual rotation is not enabled"
            configclient = boto3.client('config')    
            response = configclient.put_evaluations(
                        Evaluations=[
                            {
                                'ComplianceResourceType': 'AWS::KMS::Key',
                                'ComplianceResourceId': str(keyid),
                                'ComplianceType': compliance_type,
                                'Annotation': annotation,
                                'OrderingTimestamp': invoking_event['notificationCreationTime']
                            },
                        ],
                        ResultToken=event['resultToken'])
            print(response)
            