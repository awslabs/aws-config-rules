import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
from datetime import datetime
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
GUARDDUTY_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'guardduty':
            return GUARDDUTY_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('GUARDDUTY_UNTREATED_FINDINGS')

class ComplianceTestCases(unittest.TestCase):

    rule_valid_parameters = '{"daysLowSev":"20", "daysMediumSev":"10", "daysHighSev":"3"}'
    rule_invalid_parameters = '{"daysLowSev":"Twenty", "daysMediumSev":"-10.0", "daysHighSev":"None"}'

    gd_detector_list_enabled = {
        "DetectorIds": [
            "fab515984fc563fa95f7ab82c5dd69c7"
        ],
    }

    gd_detector_list_disabled = {
        "DetectorIds": [
        ],
    }

    gd_detector_status_active = {
        "Status": "ENABLED",
        "FindingPublishingFrequency": "SIX_HOURS",
        "CreatedAt": "2019-04-17T12:06:08.108Z"
    }

    gd_detector_status_suspended = {
        "Status": "DISABLED",
        "FindingPublishingFrequency": "SIX_HOURS",
        "CreatedAt": "2019-04-17T12:06:08.108Z"
    }

    gd_empty_findings_list = {
        "FindingIds": [
        ],
        "NextToken": ""
    }

    gd_findings_list = {
        "FindingIds": [
            "42b5159faf35b2b33df670ac2aa4b943"
        ],
        "NextToken": ""
    }

    gd_finding_lowSev_compliant = {
        "Findings": [
            {
                "Severity": 2,
                "Id": "42b5159faf35b2b33df670ac2aa4b943",
                "CreatedAt": str(datetime.utcnow()).replace(" ", "T")[:-3] + "Z",
            }
        ]
    }

    gd_finding_MediumSev_compliant = {
        "Findings": [
            {
                "Severity": 5,
                "Id": "42b5159faf35b2b33df670ac2aa4b943",
                "CreatedAt": str(datetime.utcnow()).replace(" ", "T")[:-3] + "Z",
            }
        ]
    }

    gd_finding_highSev_compliant = {
        "Findings": [
            {
                "Severity": 8,
                "Id": "42b5159faf35b2b33df670ac2aa4b943",
                "CreatedAt": str(datetime.utcnow()).replace(" ", "T")[:-3] + "Z",
            }
        ]
    }

    gd_finding_lowSev_noncompliant = {
        "Findings": [
            {
                "Severity": 2,
                "Id": "42b5159faf35b2b33df670ac2aa4b943",
                "CreatedAt": "2019-03-10T10:33:57.404Z",
            }
        ]
    }

    gd_finding_MedSev_noncompliant = {
        "Findings": [
            {
                "Severity": 5,
                "Id": "42b5159faf35b2b33df670ac2aa4b943",
                "CreatedAt": "2019-04-10T10:33:57.404Z",
            }
        ]
    }

    gd_highSev_noncompliant = {
        "Findings": [
            {
                "Severity": 8,
                "Id": "42b5159faf35b2b33df670ac2aa4b943",
                "CreatedAt": "2019-04-24T10:33:57.404Z",
            }
        ]
    }

    def setUp(self):
        pass

    # Common test scenario 1
    def test_guardduty_disabled(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_disabled)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Common test scenario 2
    def test_guardduty_suspended(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_disabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_suspended)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Common test scenario 3
    def test_guardduty_invalid_parameters(self):
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_invalid_parameters), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException', 'Invalid value for parameter \'daysLowSev\', Expected Number of Days in digits.')

    # Scenario 3
    def test_guardduty_no_findings(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_empty_findings_list)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '123456789012', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4a
    def test_guardduty_lowsev_non_compliant(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_findings_list)
        GUARDDUTY_CLIENT_MOCK.get_findings = MagicMock(return_value=self.gd_finding_lowSev_noncompliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '42b5159faf35b2b33df670ac2aa4b943', 'AWS::::Account', 'This AWS GurdDuty Low Severity finding is older than 20 days.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4b
    def test_guardduty_mediumsev_non_compliant(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_findings_list)
        GUARDDUTY_CLIENT_MOCK.get_findings = MagicMock(return_value=self.gd_finding_MedSev_noncompliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '42b5159faf35b2b33df670ac2aa4b943', 'AWS::::Account', 'This AWS GurdDuty Medium Severity finding is older than 10 days.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4c
    def test_guardduty_highsev_non_compliant(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_findings_list)
        GUARDDUTY_CLIENT_MOCK.get_findings = MagicMock(return_value=self.gd_highSev_noncompliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', '42b5159faf35b2b33df670ac2aa4b943', 'AWS::::Account', 'This AWS GurdDuty High Severity finding is older than 3 days.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5a
    def test_guardduty_lowsev_compliant(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_findings_list)
        GUARDDUTY_CLIENT_MOCK.get_findings = MagicMock(return_value=self.gd_finding_lowSev_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '42b5159faf35b2b33df670ac2aa4b943', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5b
    def test_guardduty_mediumsev_compliant(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_findings_list)
        GUARDDUTY_CLIENT_MOCK.get_findings = MagicMock(return_value=self.gd_finding_MediumSev_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '42b5159faf35b2b33df670ac2aa4b943', 'AWS::::Account'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5c
    def test_guardduty_highsev_compliant(self):
        RULE.ASSUME_ROLE_MODE = False
        GUARDDUTY_CLIENT_MOCK.list_detectors = MagicMock(return_value=self.gd_detector_list_enabled)
        GUARDDUTY_CLIENT_MOCK.get_detector = MagicMock(return_value=self.gd_detector_status_active)
        GUARDDUTY_CLIENT_MOCK.list_findings = MagicMock(return_value=self.gd_findings_list)
        GUARDDUTY_CLIENT_MOCK.get_findings = MagicMock(return_value=self.gd_finding_highSev_compliant)
        response = RULE.lambda_handler(build_lambda_scheduled_event(self.rule_valid_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', '42b5159faf35b2b33df670ac2aa4b943', 'AWS::::Account'))
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
