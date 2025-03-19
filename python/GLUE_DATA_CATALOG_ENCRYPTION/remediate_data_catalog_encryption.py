import boto3, logging

def lambda_handler(event, context):
    glue_client = boto3.client('glue')
    kms_key_arn = create_kms_key() #create kmskey

    glue_client.put_data_catalog_encryption_settings(
    DataCatalogEncryptionSettings={
        'EncryptionAtRest': {
            'CatalogEncryptionMode': 'SSE-KMS',
            'SseAwsKmsKeyId': kms_key_arn
        },
        'ConnectionPasswordEncryption': {
            'ReturnConnectionPasswordEncrypted': True,
            'AwsKmsKeyId': kms_key_arn
        }
    }
)

def create_kms_key():
    """This function creates a symmetric KMS key and returns its ARN"""
    kms_client = boto3.client('kms')
    response = kms_client.create_key(
        Description='This key was created to secure and encrypt AWS Glue data catalog',
        KeyUsage='ENCRYPT_DECRYPT', #Alternative is 'SIGN_VERIFY'|
        CustomerMasterKeySpec= 'SYMMETRIC_DEFAULT', #Alternatives are 'RSA_2048'|'RSA_3072'|'RSA_4096'|'ECC_NIST_P256'|'ECC_NIST_P384'|'ECC_NIST_P521'|'ECC_SECG_P256K1'|'
        Origin='AWS_KMS', #Alternatives are |'EXTERNAL'|'AWS_CLOUDHSM',
        Tags=[
            {
                'TagKey': 'string',
                'TagValue': 'string'
            },
        ]
    )
    
    kms_key_arn = response['KeyMetadata']['Arn']
    logging.info('KMS KEY CREATED: ' +  str(kms_key_arn))
    return kms_key_arn