import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    import mock
    from mock import MagicMock
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EC2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        elif client_name == 'sts':
            return STS_CLIENT_MOCK
        elif client_name == 'ec2':
            return EC2_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK')

class NonCompliantResourcesTest(unittest.TestCase):

    def describe_snapshots_side_effect(self, OwnerIds=None, RestorableByUserIds=None, MaxResults=None, NextToken=None, Filters=None):
        next_token = "ABC=="
        first_response = {'NextToken': '{}'.format(next_token),
                          'Snapshots': [{'SnapshotId': 'snap-9a0a02f7'}]}
        final_response = {'Snapshots': [{'SnapshotId': 'snap-0daeb11514fba831a'}, {'SnapshotId': 'snap-n6F9ou1J7c'}, {'SnapshotId': 'snap-w4M0GJ0b0A'}, {'SnapshotId': 'snap-x1O8LF8d5M'}, {'SnapshotId': 'snap-N9L8Lv7P9b'}, {'SnapshotId': 'snap-R0j9Yb9Q5Q'}, {'SnapshotId': 'snap-j0h6NT5W5n'}, {'SnapshotId': 'snap-a4d2Dm1V2A'}, {'SnapshotId': 'snap-B0L5mx6R0t'}, {'SnapshotId': 'snap-m5U5kN4e5d'}, {'SnapshotId': 'snap-B5r3rm5D9R'}, {'SnapshotId': 'snap-h8b1yj3P4A'}, {'SnapshotId': 'snap-k4Z9bh4H8j'}, {'SnapshotId': 'snap-P2q7MZ6v1T'}, {'SnapshotId': 'snap-I0W2Bv2k4w'}, {'SnapshotId': 'snap-J4T2NN1F1L'}, {'SnapshotId': 'snap-Z6w9rM0f3j'}, {'SnapshotId': 'snap-b5I5Vc8f9p'}, {'SnapshotId': 'snap-f2p4zC7W9a'}, {'SnapshotId': 'snap-h2O7iR8l1K'}, {'SnapshotId': 'snap-K2d9jH2t6E'}, {'SnapshotId': 'snap-L9u2Dr0N4Y'}, {'SnapshotId': 'snap-E6n0Jg7I2S'}, {'SnapshotId': 'snap-K1Q7Cy3O9v'}, {'SnapshotId': 'snap-u8S1NK3R8w'}, {'SnapshotId': 'snap-q2Y3Rx0C1W'}, {'SnapshotId': 'snap-n8v5hu8h4y'}, {'SnapshotId': 'snap-x8d5Ac3G6l'}, {'SnapshotId': 'snap-S5g6FG5b3H'}, {'SnapshotId': 'snap-j4R7Hk6w8L'}, {'SnapshotId': 'snap-e8x1nR3l0C'}, {'SnapshotId': 'snap-o7r1Ea6l4G'}, {'SnapshotId': 'snap-i8n2qz0b9M'}, {'SnapshotId': 'snap-n3X1HJ5j1l'}, {'SnapshotId': 'snap-Q1J9rU7J3V'}, {'SnapshotId': 'snap-A1A6iY5a2o'}, {'SnapshotId': 'snap-Q0F7oC2m0l'}, {'SnapshotId': 'snap-g5x4Lv2i7f'}, {'SnapshotId': 'snap-r2A4oY1l8a'}, {'SnapshotId': 'snap-v7Y9FN5K0V'}, {'SnapshotId': 'snap-F0M8CQ9t3f'}, {'SnapshotId': 'snap-w3V5tt8A9t'}, {'SnapshotId': 'snap-z9V3Fd4h3D'}, {'SnapshotId': 'snap-y9k9mW3r8J'}, {'SnapshotId': 'snap-e9n4pI0u1L'}, {'SnapshotId': 'snap-H1s9jO5P2H'}, {'SnapshotId': 'snap-T1F8yJ9H4b'}, {'SnapshotId': 'snap-G4E5HB4y1j'}, {'SnapshotId': 'snap-Y9s4aH5h4u'}, {'SnapshotId': 'snap-U7F1jk4d6c'}, {'SnapshotId': 'snap-Q2w0Gx0d2u'}, {'SnapshotId': 'snap-r2x2Ux4Z0i'}, {'SnapshotId': 'snap-G8N8xq7j8u'}, {'SnapshotId': 'snap-V8R2mR6o5t'}, {'SnapshotId': 'snap-p4u8xm3u2y'}, {'SnapshotId': 'snap-J2i9yJ1X2p'}, {'SnapshotId': 'snap-u9R9Hw3G3k'}, {'SnapshotId': 'snap-h0t3dv3v3E'}, {'SnapshotId': 'snap-y1H3YJ0P5a'}, {'SnapshotId': 'snap-g6V6rW0Z3n'}, {'SnapshotId': 'snap-F8a3Fi8o9R'}, {'SnapshotId': 'snap-g4t0UN8Z8t'}, {'SnapshotId': 'snap-S0K5wD0T7u'}, {'SnapshotId': 'snap-Q2W0nc5z9R'}, {'SnapshotId': 'snap-g1f7sV2M5D'}, {'SnapshotId': 'snap-j5e7WA1q8G'}, {'SnapshotId': 'snap-l5J6gP0M2J'}, {'SnapshotId': 'snap-d3b0gm9Q8d'}, {'SnapshotId': 'snap-t5G3rd1H6m'}, {'SnapshotId': 'snap-q9k7jr1T7j'}, {'SnapshotId': 'snap-c4w5xQ9d1t'}, {'SnapshotId': 'snap-t5O7Io1P8B'}, {'SnapshotId': 'snap-p0q7XT7Q7m'}, {'SnapshotId': 'snap-I1G4nC4x1J'}, {'SnapshotId': 'snap-e7Z3Zr7S9m'}, {'SnapshotId': 'snap-I7m3Qf6H4w'}, {'SnapshotId': 'snap-Q6J4bG3G4D'}, {'SnapshotId': 'snap-B7S2LU4b7d'}, {'SnapshotId': 'snap-v6V2pr7h2j'}, {'SnapshotId': 'snap-S3v0Sb4Y5E'}, {'SnapshotId': 'snap-B9T8Us9c2J'}, {'SnapshotId': 'snap-s9R3Yu8O0Q'}, {'SnapshotId': 'snap-Q3U0DL5F7e'}, {'SnapshotId': 'snap-U5V4bw3l9q'}, {'SnapshotId': 'snap-f7q6Xv2T6p'}, {'SnapshotId': 'snap-e7b2rS3w8q'}, {'SnapshotId': 'snap-R9A9cd7O2n'}, {'SnapshotId': 'snap-S2F7yL0F6t'}, {'SnapshotId': 'snap-V4a4yQ2d2f'}, {'SnapshotId': 'snap-r2Q1yv9v8E'}, {'SnapshotId': 'snap-Z3H2yz4j7X'}, {'SnapshotId': 'snap-S4f5SU2A7M'}, {'SnapshotId': 'snap-S9H5QK5m7a'}, {'SnapshotId': 'snap-T3g3kH4h5i'}, {'SnapshotId': 'snap-X7x5vS8I4A'}, {'SnapshotId': 'snap-w7b9qd6l9t'}, {'SnapshotId': 'snap-x9v6fy5v4A'}, {'SnapshotId': 'snap-H3V4eB0O4l'}, {'SnapshotId': 'snap-Y2y1ys1A4L'}, {'SnapshotId': 'snap-K9O1gb6o3H'}, {'SnapshotId': 'snap-H5f3kO1L9L'}]}
        if Filters == [{'Name':'owner-id', 'Values':['123456789012']}] and NextToken is None and OwnerIds[0] == '123456789012' and RestorableByUserIds[0] == 'all' and MaxResults == 1000:
            return first_response
        elif NextToken == next_token:
            return final_response

# Checks for scenario wherein non-compliant resources are present and pagination exists
    def test_scenario_2_all_noncompliant_resources(self):
        EC2_CLIENT_MOCK.describe_snapshots.side_effect = self.describe_snapshots_side_effect
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='NON_COMPLIANT',
                                                     compliance_resource_id='123456789012',
                                                     annotation='Public Amazon EBS Snapshot: snap-9a0a02f7,snap-0daeb11514fba831a,snap-n6F9ou1J7c,snap-w4M0GJ0b0A,snap-x1O8LF8d5M,snap-N9L8Lv7P9b,snap-R0j9Yb9Q5Q,snap-j0h6NT5W5n,snap-a4d2Dm1V2A,snap-B0L5mx6R0t,snap-m5U5kN4e5d,snap-B5r3rm5D9R,snap-h8b1yj3P4A,s[...truncated]')]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

# Checks for scenario wherein no non-compliant resources are present
class CompliantResourcesTest(unittest.TestCase):
    lambda_event = {}

    def test_scenario_1_compliant_resources(self):
        describe_snapshots_result = {'Snapshots': []}
        EC2_CLIENT_MOCK.describe_snapshots = MagicMock(return_value=describe_snapshots_result)
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [build_expected_response(compliance_type='COMPLIANT',
                                                     compliance_resource_id='123456789012', compliance_resource_type=DEFAULT_RESOURCE_TYPE)]
        assert_successful_evaluation(self, lambda_result, expected_response, len(lambda_result))

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
