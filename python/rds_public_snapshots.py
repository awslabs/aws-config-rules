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
            break
    if public:
        return {
            "compliance_type":"NON_COMPLIANT",
            "annotation":'The RDS snapshot is shared publicly.'
        }
    else:
        return {
            "compliance_type":"COMPLIANT",
            "annotation":'The RDS snapshot is not shared publicly.'
        }
    
# Check whether the resource has been deleted. If it has, then the evaluation is unnecessary.
def is_applicable(configurationItem, event):
    status              = configurationItem['configurationItemStatus']
    eventLeftScope      = event['eventLeftScope']
    return (status == 'OK' or status == 'ResourceDiscovered') and eventLeftScope == False

def lambda_handler(event, context):
    log.debug('Event %s', event) 
    invoking_event      = json.loads(event['invokingEvent'])
    configuration_item  = invoking_event["configurationItem"]
    if is_applicable(configuration_item,event):
        evaluation      = evaluate_compliance(configuration_item)
    else:
        evaluation      = {
            "compliance_type":"NOT_APPLICABLE",
            "annotation":"The RDS Snapshot has been deleted."
        }
    config              = boto3.client('config')

    response            = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType':    invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId':      invoking_event['configurationItem']['resourceId'],
               'ComplianceType':            evaluation["compliance_type"],
               "Annotation":                evaluation["annotation"],
               'OrderingTimestamp':         invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken      = event['resultToken'])
