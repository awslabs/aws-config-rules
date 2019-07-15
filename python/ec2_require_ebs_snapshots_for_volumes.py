#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure all EC2 Volumes have a recent EC2 Snapshot
#
# Trigger Type: Periodic and Change Triggered
# Scope: Volumes
# Required Parameters: requiredSnapshotFrequencyHours
# Example Value: 10

import boto3, botocore
import json
import logging
from datetime import tzinfo, datetime, timedelta

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# http://stackoverflow.com/questions/796008/cant-subtract-offset-naive-and-offset-aware-datetimes
ZERO = timedelta(0)
class UTC(tzinfo):
    def utcoffset(self, dt):
        return ZERO
    def tzname(self, dt):
        return "UTC"
    def dst(self, dt):
        return ZERO
utc = UTC()

config = boto3.client('config')
ec2 = boto3.client('ec2')

# Removes Evaluations for deleted resources, non-recorded resources, and resources that are not applicable to the rule
def evaluate_configuration_change_compliance(invoking_event, event_left_scope):
    evaluations = []
    config_item = invoking_event['configurationItem']
    if config_item['resourceType'] != 'AWS::EC2::Volume' or event_left_scope or config_item['configurationItemStatus'] in ['ResourceDeletedNotRecorded', 'ResourceNotRecorded', 'ResourceDeleted']:
        evaluations.append(
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': config_item['resourceId'],
                'ComplianceType': 'NOT_APPLICABLE',
                'OrderingTimestamp': datetime.now(utc)
            }
        )
    
    return evaluations

# Verifies that all volumes captured by the AWSConfig service have had a snapshot taken within the last <required_snapshot_req_hours> hours
def evaluate_scheduled_compliance(invoking_event, required_snapshot_freq_hours):
    evaluations = []
    oldest_snapshot_allowed_time = datetime.now(utc) - timedelta(hours = required_snapshot_freq_hours)
    
    # List current volumes from Config
    volumes = list_config_discovered_volumes()
    for volume in volumes:
        # Skip volumes that have been created recently
        volume_state = get_latest_state(volume)
        if volume_state['resourceCreationTime'] > oldest_snapshot_allowed_time:
            continue
        
        # Retrieve the completed snapshots for each volume
        snapshots = retrieve_snapshots_for_volume(volume)

        compliance = 'NON_COMPLIANT'
        for snapshot in snapshots:
            # Set to COMPLIANT only if the completed snapshot was initiated within the expected frequency
            if snapshot['StartTime'] > oldest_snapshot_allowed_time:
                compliance = 'COMPLIANT'
            
        evaluations.append(
            {
                'ComplianceResourceType': volume['resourceType'],
                'ComplianceResourceId': volume['resourceId'],
                'ComplianceType': compliance,
                'OrderingTimestamp': datetime.now(utc)
            }
        )
    
    return evaluations

# Retrieves the completed snapshots for the provided volume
def retrieve_snapshots_for_volume(volume):
    snapshots = ec2.describe_snapshots(
       Filters=[
           {
               'Name': 'volume-id',
               'Values': [
                   volume['resourceId'],
               ]
           },
           {
               'Name': 'status',
               'Values': [
                   'completed',
                ]
            },
        ],
    )
    return snapshots['Snapshots']

# List current volumes from AWSConfig
def list_config_discovered_volumes():
    volumes = []
    ldr_pagination_token = ''
    while True:
        discovered_volumes_response = config.list_discovered_resources(
            resourceType='AWS::EC2::Volume',
            nextToken=ldr_pagination_token
        )
        volumes.extend(discovered_volumes_response['resourceIdentifiers'])
        if 'nextToken' in discovered_volumes_response:
            ldr_pagination_token = discovered_volumes_response['nextToken']
        else:
            break
    
    return volumes

# Get the most recent state of the volume from AWSConfig
def get_latest_state(volume):
    latest_state_list = config.get_resource_config_history(
        resourceType=volume['resourceType'],
        resourceId=volume['resourceId'],
        limit=1
    )
    return latest_state_list['configurationItems'][0]

def lambda_handler(event, context):
    invoking_event = json.loads(event['invokingEvent'])
    rule_parameters = json.loads(event['ruleParameters'])
    
    required_snapshot_freq_hours = 0
    if 'requiredSnapshotFrequencyHours' in rule_parameters:
        required_snapshot_freq_hours = int(rule_parameters['requiredSnapshotFrequencyHours'])
    if required_snapshot_freq_hours <= 0:
        raise Exception('requiredSnapshotFrequencyHours parameter must be a greater than 0')

    if invoking_event['messageType'] == 'ConfigurationItemChangeNotification':
        evaluations = evaluate_configuration_change_compliance(invoking_event, event['eventLeftScope'])
    elif invoking_event['messageType'] == 'ScheduledNotification':
        evaluations = evaluate_scheduled_compliance(invoking_event, required_snapshot_freq_hours)
    else:
        raise Exception('Unexpected message type ' + str(invoking_event))
    
    # Report Evaluations to the AWSConfig service
    while (evaluations):
        response = config.put_evaluations(
            Evaluations = evaluations[:100],
            ResultToken = event['resultToken'])
        if 'FailedEvaluations' in response and response['FailedEvaluations']:
            raise Exception('Failed to report all evaluations successfully to the AWSConfig service. Failed: ' + str(response['FailedEvaluations']))
        del evaluations[:100]
