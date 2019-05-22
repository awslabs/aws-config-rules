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
DEFAULT_RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
CLOUDTRAIL_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'cloudtrail':
            return CLOUDTRAIL_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('CLOUDTRAIL_S3_DATAEVENTS_ENABLED')
S3_DATA_RESOURCE_TYPE = 'AWS::S3::Object'

class ComplianceTest(unittest.TestCase):

    rule_parameter_valid = '{"S3BucketName":"test, test2, test3"}'
    trail_list = {'trailList':[{"Name":"trail1", "HasCustomEventSelectors": True, "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test", "HomeRegion": "us-east-1"}, {"Name":"trail2", "HasCustomEventSelectors": True, "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test", "HomeRegion": "us-east-1"}, {"Name":"trail3", "HasCustomEventSelectors": False, "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test", "HomeRegion": "us-east-1"}]}


    #Gherkin scenario 1: Invalid rule parameter value
    def test_invalid_rule_parameter_value(self):
        invalid_rule_parameter_value = '{"S3BucketName":"abcd,a_bcd,1.2.3.4,ab,qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm"}'
        response = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters=invalid_rule_parameter_value), '{}')
        assert_customer_error_response(self, response, 'InvalidParameterValueException', "The following value in S3BucketName rule parameter is not valid: a_bcd.")

    #Gherkin scenario 2: No trail
    def test_no_trail(self):
        empty_trail_list = {'trailList':[]}
        CLOUDTRAIL_CLIENT_MOCK.describe_trails = MagicMock(return_value=empty_trail_list)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), '{}')
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    #Gherkin scenario 3: Trail with no custom event selector
    def test_trails_with_no_event_selectors(self):
        trail_list = {'trailList':[{"Name":"trail1", "HasCustomEventSelectors": False, "HomeRegion": "us-east-1"}, {"Name":"trail2", "HasCustomEventSelectors": False, "HomeRegion": "us-east-1"}]}
        CLOUDTRAIL_CLIENT_MOCK.describe_trails = MagicMock(return_value=trail_list)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), '{}')
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account', 'No AWS CloudTrail Trail is configured to log data events for Amazon S3.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Gherkin scenario 4: Trail with no custom event selector for S3
    def test_trails_with_no_event_selectors_for_s3(self):
        event_selector_output = []
        event_selector_output.append(build_event_selector_output('test', 'AWS::NotS3'))
        event_selector_output.append(build_event_selector_output('test', 'AWS::NotS3Test2'))
        CLOUDTRAIL_CLIENT_MOCK.describe_trails = MagicMock(return_value=self.trail_list)
        CLOUDTRAIL_CLIENT_MOCK.get_event_selectors = MagicMock(side_effect=event_selector_output)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), '{}')
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account', 'No AWS CloudTrail Trail is configured to log data events for Amazon S3.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Gherkin scenario 5: Trail with S3 event selector for select buckets not matching rule parameter
    def test_trails_s3_custom_check_nc(self):
        event_selector_output = []
        event_selector_output.append(build_event_selector_output(['arn:aws:s3:::test/']))
        event_selector_output.append(build_event_selector_output(['arn:aws:s3:::test2/']))
        CLOUDTRAIL_CLIENT_MOCK.describe_trails = MagicMock(return_value=self.trail_list)
        CLOUDTRAIL_CLIENT_MOCK.get_event_selectors = MagicMock(side_effect=event_selector_output)
        response = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.rule_parameter_valid), '{}')
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '123456789012', 'AWS::::Account', "AWS CloudTrail trails do not log S3 data events for buckets: ['test3']."))
        assert_successful_evaluation(self, response, resp_expected)

    #Gherkin scenario 6: Trail with S3 event selector for select buckets matching rule parameter
    def test_trails_s3_custom_check_c(self):
        event_selector_output = []
        event_selector_output.append(build_event_selector_output(['arn:aws:s3:::test/', 'arn:aws:s3:::test2/']))
        event_selector_output.append(build_event_selector_output(['arn:aws:s3:::test3/']))
        CLOUDTRAIL_CLIENT_MOCK.describe_trails = MagicMock(return_value=self.trail_list)
        CLOUDTRAIL_CLIENT_MOCK.get_event_selectors = MagicMock(side_effect=event_selector_output)
        response = RULE.lambda_handler(build_lambda_scheduled_event(rule_parameters=self.rule_parameter_valid), '{}')
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    #Gherkin scenario 7: Trail with S3 event selector for all buckets
    def test_trails_default_check(self):
        event_selector_output = []
        event_selector_output.append(build_event_selector_output(['arn:aws:s3:::test/']))
        event_selector_output.append(build_event_selector_output(['arn:aws:s3']))
        CLOUDTRAIL_CLIENT_MOCK.describe_trails = MagicMock(return_value=self.trail_list)
        CLOUDTRAIL_CLIENT_MOCK.get_event_selectors = MagicMock(side_effect=event_selector_output)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), '{}')
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

def build_event_selector_output(values, resource_type=S3_DATA_RESOURCE_TYPE):
    return {'EventSelectors':[{'DataResources':[{'Type': resource_type, 'Values': values}]}]}

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
