import sys
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EMR::Cluster'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
emr_client_mock = MagicMock()
ec2_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        if client_name == 'sts':
            return sts_client_mock
        if client_name == 'emr':
            return emr_client_mock
        if client_name == 'ec2':
            return ec2_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('EMR_MASTER_NO_PUBLIC_IP')


class SampleTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        pass

    def test_sample(self):
        self.assertTrue(True)

    #def test_sample_2(self):
    #    rule.ASSUME_ROLE_MODE = False
    #    response = rule.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, self.rule_parameters), {})
    #    resp_expected = []
    #    resp_expected.append(build_expected_response('NOT_APPLICABLE', 'some-resource-id', 'AWS::IAM::Role'))
    #    assert_successful_evaluation(self, response, resp_expected)

####################
# Helper Functions #
####################
class TestCustomerInput(unittest.TestCase):

    #Test for when no clusters are RUNNING or WAITNG
    def test_no_running_or_waiting_cluster(self):
        no_clusters = {"Clusters": []}
        emr_client_mock.list_clusters = MagicMock(return_value=no_clusters)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE',
                                                     compliance_resource_id='123456789012',
                                                     compliance_resource_type=DEFAULT_RESOURCE_TYPE))
        assert_successful_evaluation(self, response, resp_expected)


    #Test for when the cluster is in a Private Subnet but EIP was attached and then detached from the master node
    def test_running_cluster_valid_EIP_removed(self):
        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}]}
        list_instances_valid = {"Instances": [{"Ec2InstanceId": "i-0e98faaaa8a99", "PublicDnsName": "ec2-1-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}

        described_instances = {"Reservations": [{"Instances": [{"InstanceId": "i-0e98faaaa8a99", "PublicDnsName": ""}]}]}

        emr_client_mock.list_clusters = MagicMock(return_value=listcluster_valid_running)
        emr_client_mock.list_instances = MagicMock(return_value=list_instances_valid)
        ec2_client_mock.describe_instances = MagicMock(return_value=described_instances)

        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA',
                                                     compliance_resource_type='AWS::EMR::Cluster'))

        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected)

    #Test for when the cluster is in RUNNING state and master node as no public IP, COMPLIANT
    def test_running_cluster_valid(self):
        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}]}
        list_instances_valid = {"Instances": [{"Ec2InstanceId": "i-0e98faaaa8a99", "PublicDnsName": "", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}
        described_instances = {"Reservations": [{"Instances": [{"InstanceId": "i-0e98faaaa8a99", "PublicDnsName": ""}]}]}

        emr_client_mock.list_clusters = MagicMock(return_value=listcluster_valid_running)
        emr_client_mock.list_instances = MagicMock(return_value=list_instances_valid)
        ec2_client_mock.describe_instances = MagicMock(return_value=described_instances)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA',
                                                     compliance_resource_type='AWS::EMR::Cluster'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected)

    #Test for when the cluster is in RUNNING state and master node as a public IP, NON-COMPLIANT
    def test_running_cluster_invalid(self):
        listcluster_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}]}
        list_instances_valid = {"Instances": [{"Ec2InstanceId": "i-0e98faaaa8a99", "PublicDnsName": "ec2-1-1-1-1.compute-1.amazonaws.com", "PrivateDnsName": "ip-10-0-1-204.ec2.internal"}]}
        described_instances = {"Reservations": [{"Instances": [{"InstanceId": "i-0e98faaaa8a99", "PublicDnsName": "ec2-1-1-1-1.compute-1.amazonaws.com"}]}]}

        emr_client_mock.list_clusters = MagicMock(return_value=listcluster_valid_running)
        emr_client_mock.list_instances = MagicMock(return_value=list_instances_valid)
        ec2_client_mock.describe_instances = MagicMock(return_value=described_instances)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT',
                                                     compliance_resource_id='j-AAAAA0AAAAA',
                                                     compliance_resource_type='AWS::EMR::Cluster',
                                                     annotation="The EMR Cluster's master has a public IP"))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected)


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

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                testClass.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(testClass, response, customerErrorCode=None, customerErrorMessage=None):
    if customerErrorCode:
        testClass.assertEqual(customerErrorCode, response['customerErrorCode'])
    if customerErrorMessage:
        testClass.assertEqual(customerErrorMessage, response['customerErrorMessage'])
    testClass.assertTrue(response['customerErrorCode'])
    testClass.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        testClass.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        testClass.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    sts_client_mock.reset_mock(return_value=True)
    sts_client_mock.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
