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


def evaluate_compliance(configuration_item):

    # Start as compliant
    compliance_type = 'COMPLIANT'
    annotation = "S3 bucket has default encryption enabled."

    # Check if resource was deleted
    if configuration_item['configurationItemStatus'] == "ResourceDeleted":
        compliance_type = 'NOT_APPLICABLE'
        annotation = "This resource was deleted."

    # Check resource for applicability
    elif configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        compliance_type = 'NOT_APPLICABLE'
        annotation = "The rule doesn't apply to resources of type " \
                     + configuration_item["resourceType"] + "."

    # Check bucket for default encryption
    else:
        try:
            response = s3.get_bucket_encryption(
                Bucket=configuration_item["resourceName"]
            )
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
    configuration_item = invoking_event["configurationItem"]
    evaluation = evaluate_compliance(configuration_item)

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
