#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Description: Check if any s3 bucket has bucket policy and if it does mark it non-compliant
#
# Trigger Type: Change Triggered
# Scope of Changes: S3:Instance
# Accepted Parameters: None
# Your Lambda function execution role will need to have a policy that provides the appropriate
# permissions.  Here is a policy that you can consider.  You should validate this for your own
# environment
#{
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
#       {
#            "Effect": "Allow",
#            "Action": [
#                "config:PutEvaluations"
#            ],
#            "Resource": "*"
#        }
#    ]
#}
#

import boto3
import json
import logging

log = logging.getLogger()
log.setLevel(logging.DEBUG)
APPLICABLE_RESOURCES = ["AWS::S3::Bucket"]


def evaluate_compliance(configuration_item):
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

    bucket_policy = configuration_item["supplementaryConfiguration"].get("BucketPolicy")
    if bucket_policy['policyText'] is None:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": 'Bucket Policy does not exists'
        }

    else:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": 'Bucket Policy exists'
        }


def lambda_handler(event, context):
    log.debug('Event %s', event)
    invoking_event      = json.loads(event['invokingEvent'])
    configuration_item  = invoking_event["configurationItem"]
    evaluation          = evaluate_compliance(configuration_item)
    config              = boto3.client('config')

    config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType':    invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId':      invoking_event['configurationItem']['resourceId'],
               'ComplianceType':            evaluation["compliance_type"],
               "Annotation":                evaluation["annotation"],
               'OrderingTimestamp':         invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])
