import boto3, logging, sys
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    print(event)
    
    connection_name = event['ResourceId']
    glue_client = boto3.client('glue')
    
    #get connection type because its required for update_connection
    response = glue_client.get_connection(Name=connection_name, HidePassword=False)
    connection_type = response['Connection']['ConnectionType']
    connection_properties = response['Connection']['ConnectionProperties']
    connection_properties["JDBC_ENFORCE_SSL"] = "true" #overwrite to enfore ssl

    glue_client.update_connection(
        Name=connection_name,
        ConnectionInput= {
            'Name': connection_name,
            'ConnectionType': connection_type,
            'ConnectionProperties' : connection_properties
        }
    )