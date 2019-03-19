import boto3
def publicSnapshotsTest(ec2_client, owner_id):
    snapshots = []
    next_token = None
    snapshotCount = 0
    while next_token is None or next_token:
        print("next token: {}".format(next_token))
        if next_token is None:
            snapshots_result = ec2_client.describe_snapshots(OwnerIds=[owner_id], RestorableByUserIds=['all'], MaxResults=500)
        else:
            snapshots_result = ec2_client.describe_snapshots(NextToken=next_token, MaxResults=500)
        print("snapshot count: {}".format(len(snapshots_result['Snapshots'])))
        snapshotCount = len(snapshots_result['Snapshots']) + snapshotCount
        snapshots.extend(snapshots_result['Snapshots'])
        if 'NextToken' in snapshots_result:
            next_token = snapshots_result['NextToken']
        else:
            print("snapshotCount: {}".format(snapshotCount))
            return(True, snapshots)
owner='099720109477'
ec2=boto3.client('ec2')
res = publicSnapshotsTest(ec2, owner)
owner2='956584272150'
res = publicSnapshotsTest(ec2, owner2)
