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
DEFAULT_RESOURCE_TYPE = 'AWS::ElastiCache::CacheCluster'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EC_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    sample = 123
    def client(self, client_name, *args, **kwargs):
        self.sample = 123
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'elasticache':
            return EC_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('ELASTICACHE_REDIS_CLUSTER_AUTO_BACKUP_CHECK')


def replication_groups_se(**kwargs):
    if 'Marker' not in kwargs:
        return {'ReplicationGroups': [{'ReplicationGroupId':'ABC', 'SnapshotRetentionLimit': 16}], 'Marker': 'ABC'}
    return {'ReplicationGroups': [{'ReplicationGroupId':'DEF', 'SnapshotRetentionLimit': 10}]}


class CompliantResourceTest(unittest.TestCase):

    def test_scenario_5_is_compliant(self):
        EC_CLIENT_MOCK.describe_cache_clusters = MagicMock(return_value={'CacheClusters': [{'CacheClusterId':'GHI', 'SnapshotRetentionLimit': 16, 'Engine': 'redis'}]})
        EC_CLIENT_MOCK.describe_replication_groups.side_effect = replication_groups_se
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event('{"SnapshotRetentionPeriod":"15"}'), {})
        print(lambda_result)
        assert_successful_evaluation(self, lambda_result, [build_expected_response('COMPLIANT', "GHI"),
                                                           build_expected_response('COMPLIANT', "ABC"),
                                                           build_expected_response('NON_COMPLIANT', "DEF", annotation="Automatic backup retention period for Amazon ElastiCache cluster DEF is less then 15 day(s).")
                                                          ], len(lambda_result))


class NonCompliantResourceTest(unittest.TestCase):

    def test_scenario_4_low_retention(self):
        EC_CLIENT_MOCK.describe_cache_clusters = MagicMock(return_value={'CacheClusters': [{'CacheClusterId':'ABC', 'SnapshotRetentionLimit': 16, 'Engine': 'redis'}]})
        EC_CLIENT_MOCK.describe_replication_groups = MagicMock(return_value={'ReplicationGroups': []})
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event('{"SnapshotRetentionPeriod":"15"}'), {})
        assert_successful_evaluation(self, lambda_result, [build_expected_response("COMPLIANT", "ABC")], len(lambda_result))

    def test_scenario_3_no_auto_backup(self):
        # compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None
        EC_CLIENT_MOCK.describe_cache_clusters = MagicMock(return_value={'CacheClusters': [{'CacheClusterId':'ABCD', 'SnapshotRetentionLimit': 0, 'Engine': 'redis'}]})
        EC_CLIENT_MOCK.describe_replication_groups = MagicMock(return_value={'ReplicationGroups': []})
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event('{"SnapshotRetentionPeriod":"15"}'), {})
        assert_successful_evaluation(self, lambda_result, [build_expected_response("NON_COMPLIANT", "ABCD", annotation="Automatic backup not enabled for Amazon ElastiCache cluster: ABCD")], len(lambda_result))

class ErrorTest(unittest.TestCase):

    def test_scenario_2_parameter_error(self):
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event('{"SnapshotRetentionPeriod":"-1"}'), {})
        assert_customer_error_response(self, lambda_result, customer_error_message='SnapshotRetentionPeriod value should be an integer greater than 0', customer_error_code='InvalidParameterValueException')

class NotApplicableResourceTest(unittest.TestCase):

    def test_scenario_1_no_resources(self):
        EC_CLIENT_MOCK.describe_cache_clusters = MagicMock(return_value={'CacheClusters': []})
        EC_CLIENT_MOCK.describe_replication_groups = MagicMock(return_value={'ReplicationGroups': []})
        lambda_result = RULE.lambda_handler(build_lambda_scheduled_event('{"SnapshotRetentionPeriod":"15"}'), {})
        assert_successful_evaluation(self, lambda_result, [build_expected_response("NOT_APPLICABLE", "123456789012")], len(lambda_result))

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
