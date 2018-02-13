"""
    This file made available under CC0 1.0 Universal
    (https://creativecommons.org/publicdomain/zero/1.0/legalcode)

    Description: Check that no EC2 Instances are in Public Subnet

    Trigger Type: Change Triggered
    Scope of Changes: EC2:Instance
    Accepted Parameters: None
    Your Lambda function execution role will need to have a policy that provides the appropriate
    permissions.  Here is a policy that you can consider.  You should validate this for your own
    environment

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "config:PutEvaluations",
                    "ec2:DescribeRouteTables"
                ],
                "Resource": "*"
            }
        ]
    }
"""
import logging
import json
import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

AWS_CONFIG = boto3.client('config')
AWS_EC2 = boto3.client('ec2')


def evaluate_compliance(configuration_item):
    """ Evaluate Compliance """
    subnet_id = configuration_item['configuration']['subnetId']
    vpc_id = configuration_item['configuration']['vpcId']

    class Result(object):
        """ Store Results"""
        private = True

        def __init__(self, private):
            self.private = private

        def evaluate_routes(self, routes):
            """Check Routes"""
            for route in routes:
                if route['DestinationCidrBlock'] == '0.0.0.0/0' or \
                        route['GatewayId'].startswith('igw-'):
                    self.private = False

        def result(self):
            """Return result object"""
            result = {
                'compliance_type': 'COMPLIANT',
                'annotation': 'Its in private subnet'
            }
            if self.private is False:
                result = {
                    'compliance_type': 'NON_COMPLIANT',
                    'annotation': 'Not in private subnet'
                }
            return result

    result = Result(True)

    response = AWS_EC2.describe_route_tables()

    # We need to determine if the subnetId in question is using the main
    # route table or not.  Since there is no association when using main
    # we need to see if it has any associations
    # Private subnet condition applies only when route doesn't contains
    # destination CIDR block = 0.0.0.0/0 or no Internet Gateway is attached
    subnet_using_main = True
    for i in response['RouteTables']:
        if i['VpcId'] == vpc_id:
            for j in i['Associations']:
                if j.get('SubnetId') == subnet_id:
                    result.evaluate_routes(i['Routes'])
                    subnet_using_main = False

    if subnet_using_main is not False:
        for i in response['RouteTables']:
            if i['VpcId'] == vpc_id:
                for j in i['Associations']:
                    if j['Main'] is True:
                        result.evaluate_routes(i['Routes'])

    return result.result()


def lambda_handler(event, _):
    """Lambda handler"""
    LOG.debug('Event %s', event)
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']
    evaluation = evaluate_compliance(configuration_item)

    AWS_CONFIG.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
                'ComplianceType': evaluation['compliance_type'],
                'Annotation': evaluation['annotation'],
                'OrderingTimestamp':
                    invoking_event['configurationItem']['configurationItemCaptureTime']
            },
        ],
        ResultToken=event['resultToken'])
