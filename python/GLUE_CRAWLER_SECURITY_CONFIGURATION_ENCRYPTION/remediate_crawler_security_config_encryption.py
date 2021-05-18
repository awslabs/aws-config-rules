import boto3, logging, sys
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    print(event)
    
    glue_crawler_name = event['ResourceId']
    glue_client = boto3.client('glue')
    
    configuration_name = get_crawler_security_configuartion(glue_crawler_name, glue_client)
    if not configuration_name:
        logging.info('Glue crawler has no security configuration, creating a new one now')
        new_security_configuration = create_security_configuration(glue_client, glue_crawler_name)
        change_crawler_security_configuration(glue_client, glue_crawler_name, new_security_configuration)
        
    else: #there is an existing configuration
        #get encryption status dictionary
        encryption_status = check_security_configuration(configuration_name, glue_client)
        
        #check s3 and cloudwatch encryption for security configuration 
        s3_encryption_config = encryption_status['S3Encryption']
        cloudwatch_encryption_config = encryption_status['CloudWatchEncryption']
        
        #if encryption is not enabled for both, then create a new security configuration and update the glue job
        if s3_encryption_config[next(iter(s3_encryption_config))] == 'DISABLED' or cloudwatch_encryption_config[next(iter(cloudwatch_encryption_config))] == 'DISABLED':
            new_security_configuration = create_security_configuration(glue_client, glue_crawler_name)
            change_crawler_security_configuration(glue_client, glue_crawler_name, new_security_configuration)
            logging.info(glue_crawler_name + "'s security configuration has been updated to a new one called " + new_security_configuration)
            
        else: logging.info('S3 and CloudWatch Encryption are both Enabled for ' + str(configuration_name))

def change_crawler_security_configuration(glue_client, glue_crawler_name, new_security_configuration_name):
    """This function changes the security configuartion of the glue crawler to the new_security_configuration_name"""
    glue_client.update_crawler(
        Name=glue_crawler_name,
        CrawlerSecurityConfiguration=new_security_configuration_name
    )
    

def check_security_configuration(security_configuration_name, glue_client):
    """This function checks for S3 and Cloudwatch Encryption on the given security configuration and 
    returns a dictionary of the values"""
    
    response = glue_client.get_security_configuration(
        Name=security_configuration_name
    )

    encryption_status = {}
    encryption_config = response['SecurityConfiguration']['EncryptionConfiguration']

    s3_encryption_config = encryption_config['S3Encryption'][0]
    encryption_status['S3Encryption'] = s3_encryption_config
    
    cloudwatch_encryption_config = encryption_config['CloudWatchEncryption']
    encryption_status['CloudWatchEncryption'] = cloudwatch_encryption_config
    
    return encryption_status

def get_crawler_security_configuartion(glue_crawler_name, glue_client):
    """This function returns the security configuration name of the given glue job"""
    response = glue_client.get_crawler(
        Name = glue_crawler_name  
    )
    try:
        security_configuration = response['Crawler']['CrawlerSecurityConfiguration']
    except:
        security_configuration = {}
        
    return security_configuration

def create_security_configuration(glue_client, glue_crawler_name):
    """This function creates a new encrypted security configuration"""
    
    kms_key_arn = create_kms_key()
    security_config_name = glue_crawler_name + '_SecurityConfiguration'
    try: 
        response = glue_client.create_security_configuration(
            Name= security_config_name,
            EncryptionConfiguration={
                'S3Encryption': [
                    {
                        'S3EncryptionMode': 'SSE-KMS',
                        'KmsKeyArn': kms_key_arn
                    },
                ], 
                'CloudWatchEncryption': {
                    'CloudWatchEncryptionMode': 'SSE-KMS',
                    'KmsKeyArn': kms_key_arn
                    }
                },
        )
        return response['Name']
    
    except ClientError as e:
        if e.response['Error']['Code'] == 'AlreadyExistsException':
            return security_config_name
        else:
            logging.critical('Security Configuration Creation Failed')
            sys.exit(1)
            

def create_kms_key():
    """This function creates a symmetric KMS key and returns its ARN"""
    kms_client = boto3.client('kms')
    response = kms_client.create_key(
        # Policy='string',
        Description='This key was created to secure and encrypt AWS Glue',
        KeyUsage='ENCRYPT_DECRYPT', #Alternative is 'SIGN_VERIFY'|
        CustomerMasterKeySpec= 'SYMMETRIC_DEFAULT', #Alternatives are 'RSA_2048'|'RSA_3072'|'RSA_4096'|'ECC_NIST_P256'|'ECC_NIST_P384'|'ECC_NIST_P521'|'ECC_SECG_P256K1'|'
        Origin='AWS_KMS', #Alternatives are |'EXTERNAL'|'AWS_CLOUDHSM',
        # CustomKeyStoreId='string',
        # BypassPolicyLockoutSafetyCheck=True|False,
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