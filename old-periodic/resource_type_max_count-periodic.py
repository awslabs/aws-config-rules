#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure all EC2 Instances are of a Given Type
# Description: Checks that all EC2 instances are of the type specified
#
# Trigger Type: Periodic
# Required Parameters: applicableResourceType, maxCount
# Example Value: AWS::EC2::Instance, 10
#
# See http://docs.aws.amazon.com/config/latest/APIReference/API_ListDiscoveredResources.html for resource types.

import boto3
import re, json, gzip, StringIO

def evaluate_compliance(config_items, rule_parameters):
    count = 0;

    for item in config_items:
        if (item['resourceType'] == rule_parameters['applicableResourceType']):
            count += 1

    if (count > int(rule_parameters['maxCount'])):
        return 'NON_COMPLIANT'
    else:
        return 'COMPLIANT'
 

def read_snapshot_data(s3_key, s3_bucket):
    s3_client = boto3.client('s3', region_name='us-east-1')
    s3_object = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
    gzdata = s3_object['Body'].read()
    gzfile = gzip.GzipFile(fileobj=StringIO.StringIO(gzdata))

    return json.loads(gzfile.read())
 

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters'])

    snapshot = read_snapshot_data(invoking_event['s3ObjectKey'],
            invoking_event['s3Bucket'])

    compliance_value = evaluate_compliance(snapshot['configurationItems'],
            rule_parameters)

    account_id = re.findall('AWSLogs\/(\d+)\/Config',
            invoking_event['s3ObjectKey'])[0]

    config = boto3.client('config')
    response = config.put_evaluations(
       Evaluations=[
            {
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': account_id,
                'ComplianceType': compliance_value,
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            },
       ],
       ResultToken=event['resultToken'])
 
