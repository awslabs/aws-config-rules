import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import botocore

DEFAULT_RESOURCE_TYPE = 'AWS::Elasticsearch::Domain'

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
ES_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'es':
            return ES_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('ELASTICSEARCH_ENCRYPTED_AT_REST')

class ComplianceTest(unittest.TestCase):

    list_domains_scenario_1 = {'DomainNames':[{'DomainName':'domain1'}, {'DomainName':'domain2'}]}
    describe_domain_scenario_1 = {"DomainStatusList": [{"EncryptionAtRestOptions":{"Enabled":True}, "DomainName":"domain1"}, {"EncryptionAtRestOptions":{"Enabled":True}, "DomainName":"domain2"}]}
    list_domains_scenario_2 = {'DomainNames':[{'DomainName':'domain1'}, {'DomainName':'domain2'}]}
    describe_domain_scenario_2 = {"DomainStatusList": [{"EncryptionAtRestOptions":{"Enabled":False}, "DomainName":"domain1"}, {"EncryptionAtRestOptions":{"Enabled":False}, "DomainName":"domain2"}]}
    list_domains_scenario_3 = {'DomainNames':[{'DomainName':'domain1'}, {'DomainName':'domain2'}, {'DomainName':'domain3'}, {'DomainName':'domain4'}, {'DomainName':'domain5'}, {'DomainName':'domain6'}]}
    describe_domain_scenario_3 = {"DomainStatusList": [{"EncryptionAtRestOptions":{"Enabled":False}, "DomainName":"domain1"}, {"EncryptionAtRestOptions":{"Enabled":True}, "DomainName":"domain2"}, {"EncryptionAtRestOptions":{"Enabled":False}, "DomainName":"domain3"}, {"EncryptionAtRestOptions":{"Enabled":True}, "DomainName":"domain4"}, {"EncryptionAtRestOptions":{"Enabled":False}, "DomainName":"domain5"}]}
    describe_domain_scenario_4 = {"DomainStatusList": [{"EncryptionAtRestOptions":{"Enabled":True}, "DomainName":"domain6"}]}

    def setUp(self):
        pass

    def test_scenario_1_is_null_domains(self):
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value={'DomainNames': []})
        lambda_event = build_lambda_scheduled_event(rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_2_is_compliant(self):
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.list_domains_scenario_1)
        ES_CLIENT_MOCK.describe_elasticsearch_domains = MagicMock(return_value=self.describe_domain_scenario_1)
        lambda_event = build_lambda_scheduled_event(rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'domain1'))
        resp_expected.append(build_expected_response('COMPLIANT', 'domain2'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_3_is_non_compliant(self):
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.list_domains_scenario_2)
        ES_CLIENT_MOCK.describe_elasticsearch_domains = MagicMock(return_value=self.describe_domain_scenario_2)
        lambda_event = build_lambda_scheduled_event(rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'domain1', annotation='This Amazon Elasticsearch domain is not encrypted at rest.'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'domain2', annotation='This Amazon Elasticsearch domain is not encrypted at rest.'))
        assert_successful_evaluation(self, response, resp_expected, 2)

    def test_scenario_4_multiple_domains(self):
        RULE.PAUSE_TO_AVOID_THROTTLE_SECONDS = 0
        ES_CLIENT_MOCK.list_domain_names = MagicMock(return_value=self.list_domains_scenario_3)
        ES_CLIENT_MOCK.describe_elasticsearch_domains = MagicMock(side_effect=[self.describe_domain_scenario_3, self.describe_domain_scenario_4])
        lambda_event = build_lambda_scheduled_event(rule_parameters=None)
        response = RULE.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'domain1', annotation='This Amazon Elasticsearch domain is not encrypted at rest.'))
        resp_expected.append(build_expected_response('COMPLIANT', 'domain2'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'domain3', annotation='This Amazon Elasticsearch domain is not encrypted at rest.'))
        resp_expected.append(build_expected_response('COMPLIANT', 'domain4'))
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'domain5', annotation='This Amazon Elasticsearch domain is not encrypted at rest.'))
        resp_expected.append(build_expected_response('COMPLIANT', 'domain6'))
        assert_successful_evaluation(self, response, resp_expected, evaluations_count=6)

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
