import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EMR::Cluster'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EMR_CLIENT_MOCK = MagicMock()
EC2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'emr':
            return EMR_CLIENT_MOCK
        if client_name == 'ec2':
            return EC2_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EMR_MASTER_NO_PUBLIC_IP')

class ComplianceTest(unittest.TestCase):

    #Scenario 1: If no RUNNING and WAITING clusters then return NOT_APPLICABLE
    def test_scenario_1_no_running_or_waiting_or_waiting_cluster(self):
        no_clusters = {"Clusters": []}
        EMR_CLIENT_MOCK.list_clusters = MagicMock(return_value=no_clusters)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE',
                                                     compliance_resource_id='123456789012',
                                                     compliance_resource_type="AWS::::Account"))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 2: Both DescribeInstances and ListInstances have public DNS for the master node of the cluster.
    #Test for when the cluster is in RUNNING state and master node as a public IP, NON-COMPLIANT
    def test_scenario_2_running_or_waiting_public_cluster(self):
        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}, {'Id': 'j-AAAAA000000', 'Status': {'State': 'WAITING'}}]}

        list_instances = []
        list_instances_valid_1 = {"Instances": [{"Ec2InstanceId": "i-0e98faa", "PublicDnsName": "ec2-1-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}
        list_instances.append(list_instances_valid_1)
        list_instances_valid_2 = {"Instances": [{"Ec2InstanceId": "i-aaaa8a99", "PublicDnsName": "ec2-2-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-2-204.ec2.internal"}]}
        list_instances.append(list_instances_valid_2)

        described_instances = {"Reservations": [{"Instances": [{"InstanceId": "i-0e98faa", "PublicDnsName": "ec2-1-1-1-1.compute-1.amazonaws.com"}, {"InstanceId": "i-aaaa8a99", "PublicDnsName": "ec2-2-1-1-1.compute-1.amazonaws.com"}]}]}

        EMR_CLIENT_MOCK.list_clusters = MagicMock(return_value=listcluster_valid_running)
        EMR_CLIENT_MOCK.list_instances = MagicMock(side_effect=list_instances)
        EC2_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EC2_CLIENT_MOCK,
            "paginate.return_value": [described_instances]})

        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA',
                                                     annotation="The master node of the EMR cluster has a public IP."))
        resp_expected.append(build_expected_response('NON_COMPLIANT',
                                                     compliance_resource_id='j-AAAAA000000',
                                                     annotation="The master node of the EMR cluster has a public IP."))
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 2)


    #Scenario 3: DescribeInstances doesn't have public DNS for the master node of the cluster while ListInstances has it.
    #Test for when the cluster is in a Private Subnet but EIP was attached and then detached from the master node
    def test_scenario_3_running_or_waiting_private_cluster_eip_removed(self):
        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}, {'Id': 'j-AAAAA000000', 'Status': {'State': 'WAITING'}}]}

        list_instances = []
        list_instances_invalid_1 = {"Instances": [{"Ec2InstanceId": "i-0e98faa", "PublicDnsName": "ec2-1-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}
        list_instances.append(list_instances_invalid_1)
        list_instances_invalid_2 = {"Instances": [{"Ec2InstanceId": "i-aaaa8a99", "PublicDnsName": "ec2-2-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-2-204.ec2.internal"}]}
        list_instances.append(list_instances_invalid_2)

        described_instances = {"Reservations": [{"Instances": [{"InstanceId": "i-0e98faa", "PublicDnsName": ""}, {"InstanceId": "i-aaaa8a99", "PublicDnsName": ""}]}]}

        EMR_CLIENT_MOCK.list_clusters = MagicMock(return_value=listcluster_valid_running)
        EMR_CLIENT_MOCK.list_instances = MagicMock(side_effect=list_instances)
        EC2_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EC2_CLIENT_MOCK,
            "paginate.return_value": [described_instances]})

        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA'))

        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA000000'))

        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 2)

    #Scenario 4: The ListInstances call doesn't have public DNS for the master node of the cluster.
    #Test for when the cluster is in RUNNING state and master node as no public IP, COMPLIANT
    def test_scenario_4_running_or_waiting_private_cluster(self):
        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}, {'Id': 'j-AAAAA000000', 'Status': {'State': 'WAITING'}}]}

        list_instances = []
        list_instances_valid_1 = {"Instances": [{"Ec2InstanceId": "i-0e98faa", "PublicDnsName": "", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}
        list_instances.append(list_instances_valid_1)
        list_instances_valid_2 = {"Instances": [{"Ec2InstanceId": "i-aaaa8a99", "PublicDnsName": "", "PrivateDnsName": "ip-10-0-2-204.ec2.internal"}]}
        list_instances.append(list_instances_valid_2)

        EMR_CLIENT_MOCK.list_clusters = MagicMock(return_value=listcluster_valid_running)
        EMR_CLIENT_MOCK.list_instances = MagicMock(side_effect=list_instances)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA'))
        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA000000'))
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 2)


    def test_all_scenarios(self):

        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}, {'Id': 'j-AAAAA000000', 'Status': {'State': 'WAITING'}}, {'Id': 'j-0000000AAAAA', 'Status': {'State': 'RUNNING'}}]}

        list_instances = []
        list_instances_valid_1 = {"Instances": [{"Ec2InstanceId": "i-0e98faa", "PublicDnsName": "", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}
        list_instances.append(list_instances_valid_1)
        list_instances_valid_2 = {"Instances": [{"Ec2InstanceId": "i-aaaa8a99", "PublicDnsName": "ec2-2-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-2-204.ec2.internal"}]}
        list_instances.append(list_instances_valid_2)
        list_instances_invalid_3 = {"Instances": [{"Ec2InstanceId": "i-baaa8a99", "PublicDnsName": "ec2-2-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-2-204.ec2.internal"}]}
        list_instances.append(list_instances_invalid_3)

        described_instances = {"Reservations": [{"Instances": [{"InstanceId": "i-aaaa8a99", "PublicDnsName": ""}, {"InstanceId": "i-baaa8a99", "PublicDnsName": "ec2-2-1-1-1.compute-1.amazonaws.com"}]}]}

        EMR_CLIENT_MOCK.list_clusters = MagicMock(return_value=listcluster_valid_running)
        EMR_CLIENT_MOCK.list_instances = MagicMock(side_effect=list_instances)
        EC2_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EC2_CLIENT_MOCK,
            "paginate.return_value": [described_instances]})

        resp_expected = []

        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA000000'))

        resp_expected.append(build_expected_response('NON_COMPLIANT',
                                                     compliance_resource_id='j-0000000AAAAA',
                                                     annotation="The master node of the EMR cluster has a public IP."))
        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA'))

        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 3)


####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response['customerErrorMessage'])
    test_class.assertTrue(response['customerErrorCode'])
    test_class.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
