import sys
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError
import datetime
from dateutil.tz import tzutc

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
ec2_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'ec2':
            return ec2_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK')

# Checks for scenario wherein non-compliant resources are present
class NonCompliantResourcesTest(unittest.TestCase):
    lambda_event = {}

    def setUp(self):
        self.lambda_event = build_lambda_scheduled_event()
        pass

    def describe_snapshots_side_effect(self, OwnerIds=None, RestorableByUserIds=None, MaxResults=None, NextToken=None):
        next_token = "eyJ2IjoiMiIsImMiOiI4KzJzMnlVaU13WVRJdUJpSC91TjVwcFVhRmwyd3FzMFo2V3lOWTNPRi9tL3JUcVl2b3VIb2lZQ2tZNVJTWWc4c0lSWTRQVFdEbXdpY2tkWmRTRzViVElBT1RGQURQVG0rZ2FzcGVRMUJHQis3cG9RSEFNKy9rVWJ0Rnkyall4Qlg1N3ljWUs4ZDNCVnlvT0pud1NxR2d0RHJIMFZhYmJBTzRBc2NsRnowZEJhamRiYitHUmphUi9Jc3pEK04vS1ZDcnBaNjJDSzN4Rkw3QT09IiwicyI6IjEifQ=="
        first_response = {'NextToken': '{}'.format(next_token),
                          'ResponseMetadata': {'HTTPHeaders': {'content-type': 'text/xml;charset=UTF-8',
                            'date': 'Fri, 15 Mar 2019 16:58:27 GMT',
                            'server': 'AmazonEC2',
                            'transfer-encoding': 'chunked',
                            'vary': 'Accept-Encoding'},
                           'HTTPStatusCode': 200,
                           'RequestId': '9d292dca-1d15-48aa-886f-5821e15691f2',
                           'RetryAttempts': 0},
                           'Snapshots': [{'Description': 'hvm-ssd/ubuntu-tsample151007',
                                          'Encrypted': False,
                                          'OwnerId': '123456789012',
                                          'Progress': '100%',
                                          'SnapshotId': 'snap-9a0a02f7',
                                          'StartTime': datetime.datetime(2015, 10, 8, 0, 46, 39, tzinfo=tzutc()),
                                          'State': 'completed',
                                          'VolumeId': 'vol-503ab6b0',
                                          'VolumeSize': 8}]
                         }
        final_response = {'ResponseMetadata': {'HTTPHeaders': {'content-type': 'text/xml;charset=UTF-8',
                          'date': 'Fri, 15 Mar 2019 16:55:26 GMT',
                          'server': 'AmazonEC2',
                          'transfer-encoding': 'chunked',
                          'vary': 'Accept-Encoding'},
                          'HTTPStatusCode': 200,
                          'RequestId': 'fa2f8132-c8eb-46c3-b242-4example42a',
                          'RetryAttempts': 0},
                          'Snapshots': [{'Description': 'Copied for DestinationAmi ami.',
                                        'Encrypted': False,
                                        'OwnerId': '123456789012',
                                        'Progress': '100%',
                                        'SnapshotId': 'snap-0daeb11514fba831a',
                                        'StartTime': datetime.datetime(2019, 3, 15, 14, 58, 48, 662000, tzinfo=tzutc()),
                                        'State': 'completed',
                                        'VolumeId': 'vol-ffffffff',
                                        'VolumeSize': 99}]
                          }
        if((NextToken is None) and (OwnerIds[0]=='123456789012') and (RestorableByUserIds[0]=='all') and (MaxResults==1000)):
            return(first_response)
        elif(NextToken == next_token):
            return(final_response)

# Checks for scenario wherein non-compliant resources are present and pagination exists
    def test_all_noncompliant_resources_with_pagination(self):
        ec2_client_mock.describe_snapshots.side_effect = self.describe_snapshots_side_effect
        lambda_result = rule.lambda_handler(self.lambda_event, {})
        expected_response = [build_expected_response(compliance_type='NON_COMPLIANT',
                                                    compliance_resource_id='snap-9a0a02f7',
                                                    compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation='EBS Snapshot: snap-9a0a02f7 is public'),
                            build_expected_response(compliance_type='NON_COMPLIANT', compliance_resource_id='snap-0daeb11514fba831a',
                                                    compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation='EBS Snapshot: snap-0daeb11514fba831a is public')]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

# Checks for scenario wherein no non-compliant resources are present
class CompliantResourcesTest(unittest.TestCase):
    lambda_event = {}

    def setUp(self):
        self.lambda_event = build_lambda_scheduled_event()
        pass

    def test_compliant_resources(self):
        describe_snapshots_result = {'ResponseMetadata': {'HTTPHeaders': {'content-length': '227',
                                     'content-type': 'text/xml;charset=UTF-8', 'date': 'Thu, 14 Mar 2019 12:36:41 GMT',
                                     'server': 'AmazonEC2'}, 'HTTPStatusCode': 200, 'RequestId': 'example09-ecb6-407e-9053-e8sample5f',
                                     'RetryAttempts': 0},'Snapshots': []}
        ec2_client_mock.describe_snapshots = MagicMock(return_value=describe_snapshots_result)
        lambda_result = rule.lambda_handler(self.lambda_event, {})
        expected_response = [build_expected_response(compliance_type='NOT_APPLICABLE',
                                                    compliance_resource_id='N/A', compliance_resource_type=DEFAULT_RESOURCE_TYPE)]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

# Checks for scenario wherein API call returns an error
class APIErrorTest(unittest.TestCase):
    lambda_event = {}

    def setUp(self):
        self.lambda_event = build_lambda_scheduled_event()
        pass

    def test_api_error(self):
        error_response = {'ResponseMetadata': {'HTTPHeaders': {'content-type': 'text/xml;charset=UTF-8',
                                                                'date': 'Fri, 15 Mar 2019 16:55:26 GMT',
                                                                'server': 'AmazonEC2',
                                                                'transfer-encoding': 'chunked',
                                                                'vary': 'Accept-Encoding'},
                                                                'HTTPStatusCode': 403,
                           'RequestId': 'fa2f8132-c8eb-46c3-b242-4example42a',
                           'RetryAttempts': 0},
                           'Snapshots': [{'Description': 'Copied for DestinationAmi ami.',
                                        'Encrypted': False,
                                        'OwnerId': '123456789012',
                                        'Progress': '100%',
                                        'SnapshotId': 'snap-0daeb11514fba831a',
                                        'StartTime': datetime.datetime(2019, 3, 15, 14, 58, 48, 662000, tzinfo=tzutc()),
                                        'State': 'completed',
                                        'VolumeId': 'vol-ffffffff',
                                        'VolumeSize': 99}]}
        ec2_client_mock.describe_snapshots = MagicMock(return_value=error_response)
        lambda_result = rule.lambda_handler(self.lambda_event, {})
        expected_result = []
        self.assertEqual(expected_result, lambda_result)

    #def test_sample_2(self):
    #    rule.ASSUME_ROLE_MODE = False
    #    response = rule.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_iam_role_sample, self.rule_parameters), {})
    #    resp_expected = []
    #    resp_expected.append(build_expected_response('NOT_APPLICABLE', 'some-resource-id', 'AWS::IAM::Role'))
    #    assert_successful_evaluation(self, response, resp_expected)

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
    invoking_event = '{"awsAccountId":"123456789012","messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
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
