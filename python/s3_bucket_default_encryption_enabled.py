# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Description: Check that S3 buckets have default encryption enabled.
#
# Trigger Type: Change Triggered
# Scope of Changes: S3:Bucket
# Accepted Parameters: None
# Your Lambda function execution role will need to have a policy that provides
# the appropriate permissions. Here is a policy that you can consider.
# You should validate this for your own environment.
#
# Optional Parameters:
# 1. Key: SSE_OR_KMS
#    Values: SSE, KMS
# 2. Key: KMS_ARN
#    Value: ARN of the KMS key
#
# NOTE: If you specify KMS_ARN, you must choose KMS for SSE_OR_KMS.
#
# {
#    "Version": "2012-10-17",
#    "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": [
#                "logs:CreateLogGroup",
#                "logs:CreateLogStream",
#                "logs:PutLogEvents"
#            ],
#            "Resource": "arn:aws:logs:*:*:*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "config:PutEvaluations"
#            ],
#            "Resource": "*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "s3:GetEncryptionConfiguration"
#            ],
#            "Resource": "arn:aws:s3:::*"
#        }
#    ]
# }


import boto3
import json


s3 = boto3.client("s3")
config = boto3.client('config')


APPLICABLE_RESOURCES = ["AWS::S3::Bucket"]


def evaluate_compliance(configuration_item, rule_parameters):

    # Start as non-compliant
    compliance_type = 'NON_COMPLIANT'
    annotation = "S3 bucket either does NOT have default encryption enabled, " \
                 + "has the wrong TYPE of encryption enabled, or is encrypted " \
                 + "with the wrong KMS key."

    # Check if resource was deleted
    if configuration_item['configurationItemStatus'] == "ResourceDeleted":
        compliance_type = 'NOT_APPLICABLE'
        annotation = "The resource was deleted."

    # Check resource for applicability
    elif configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        compliance_type = 'NOT_APPLICABLE'
        annotation = "The rule doesn't apply to resources of type " \
                     + configuration_item["resourceType"] + "."

    # Check bucket for default encryption
    else:
        try:
            # Encryption isn't in configurationItem so an API call is necessary
            response = s3.get_bucket_encryption(
                Bucket=configuration_item["resourceName"]
            )

            # Check if optional parameters were supplied
            if 'SSE_OR_KMS' in rule_parameters:
                if rule_parameters['SSE_OR_KMS'] == 'SSE':
                    if response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] != 'AES256':
                        compliance_type = 'NON_COMPLIANT'
                        annotation = 'S3 bucket is NOT encrypted with SSE-S3.'
                    else:
                        compliance_type = 'COMPLIANT'
                        annotation = 'S3 bucket is encrypted with SSE-S3.'
                if rule_parameters['SSE_OR_KMS'] == 'KMS':
                    if response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] != 'aws:kms':
                        compliance_type = 'NON_COMPLIANT'
                        annotation = 'S3 bucket is NOT encrypted with KMS.'
                    else:
                        if 'KMS_ARN' in rule_parameters:
                            if rule_parameters['KMS_ARN'] != response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']:
                                compliance_type = 'NON_COMPLIANT'
                                annotation = 'S3 bucket is encrypted with the wrong KMS key.'
                            else:
                                compliance_type = 'COMPLIANT'
                                annotation = 'S3 bucket is encrypted with the correct KMS key.'
                        # KMS but no ARN is specified
                        else:
                            compliance_type = 'COMPLIANT'
                            annotation = 'S3 bucket is encrypted with KMS.'
            # If we received no parameters and we made it this far, we're compliant.
            else:
                compliance_type = 'COMPLIANT'
                annotation = 'S3 bucket has default encryption enabled.'

        except:
            # If we receive an error, the default encryption flag is not set
            compliance_type = 'NON_COMPLIANT'
            annotation = 'S3 bucket does NOT have default encryption enabled.'

    return {
        "compliance_type": compliance_type,
        "annotation": annotation
    }


def lambda_handler(event, context):

    invoking_event = json.loads(event['invokingEvent'])

    # Check for oversized item
    if "configurationItem" in invoking_event:
        configuration_item = invoking_event["configurationItem"]
    elif "configurationItemSummary" in invokingEvent:
        configuration_item = invoking_event["configurationItemSummary"]

    # Optional parameters
    rule_parameters = {}
    if 'ruleParameters' in event:
        rule_parameters = json.loads(event['ruleParameters'])

    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    print('Compliance evaluation for %s: %s' % (configuration_item['resourceId'], evaluation["compliance_type"]))
    print('Annotation: %s' % (evaluation["annotation"]))

    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId':   invoking_event['configurationItem']['resourceId'],
               'ComplianceType':         evaluation["compliance_type"],
               "Annotation":             evaluation["annotation"],
               'OrderingTimestamp':      invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])
