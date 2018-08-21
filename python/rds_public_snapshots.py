#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Description: Check that no RDS snapshots are shared publicly
#
# Trigger Type: Change Triggered
# Scope of Changes: RDS:DBSnapshot
# Accepted Parameters: None


import boto3
import json
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)

def evaluate_compliance(configuration_item):
    public = False
    for v in configuration_item["supplementaryConfiguration"]["DBSnapshotAttributes"][0]["attributeValues"]:
        if v == "all":
            public = True
            continue
    if public:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : 'Snapshot shared publicly'
        }
    else:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": 'Snapshot not shared publicly'
        }
    

def lambda_handler(event, context):
    log.debug('Event %s', event) 
    invoking_event      = json.loads(event['invokingEvent'])
    configuration_item  = invoking_event["configurationItem"]
    evaluation          = evaluate_compliance(configuration_item)
    config              = boto3.client('config')

    response = config.put_evaluations(
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