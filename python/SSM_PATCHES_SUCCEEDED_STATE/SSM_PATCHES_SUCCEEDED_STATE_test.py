import sys
import json
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
SSM_CLIENT_MOCK = MagicMock()
EC2_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'ssm':
            return SSM_CLIENT_MOCK
        if client_name == 'ec2':
            return EC2_CLIENT_MOCK

        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('SSM_PATCHES_SUCCEEDED_STATE')

class ComplianceTest(unittest.TestCase):

    def test_scenario_1_compliant(self):
        '''Test scenario to test no patches in a missing or failed state
        Keyword arguments:
        self -- class ComplianceTest
        '''
        ssm_mock1()
        invoking_event = build_invoking_event("", None)
        response = RULE.lambda_handler(build_lambda_event(rule_parameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("COMPLIANT", "i-8877665544332211"))
        assert_successful_evaluation(self, response, expected_response)

    def test_scenario_2_compliant(self):
        '''Test scenario to test installed and missing state
        Keyword arguments:
        self -- class ComplianceTest
        '''
        ssm_mock2()
        invoking_event = build_invoking_event("", None)
        response = RULE.lambda_handler(build_lambda_event(rule_parameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("COMPLIANT", "i-8877665544332211"))
        assert_successful_evaluation(self, response, expected_response)

    def test_scenario_3_compliant(self):
        '''Test scenario to test installed other and failed state
        Keyword arguments:
        self -- class ComplianceTest
        '''
        ssm_mock3()
        invoking_event = build_invoking_event("", None)
        response = RULE.lambda_handler(build_lambda_event(rule_parameters='{}', invoking_event=invoking_event), "")
        expected_response = []
        expected_response.append(build_expected_response("COMPLIANT", "i-8877665544332211"))
        assert_successful_evaluation(self, response, expected_response)

####################
# Helper Functions #
####################

def build_lambda_event(rule_parameters, invoking_event):
    return {
        'executionRoleArn': 'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'ruleParameters': rule_parameters,
        'accountId': 'account-id',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken': 'token',

    }

def build_invoking_event(tags, iam_instance_profile_arn):
    invoking_event = {
        "messageType":"ConfigurationItemChangeNotification",
        "notificationCreationTime": "SAMPLE",
        "configurationItem":{
            "resourceType":"AWS::EC2::Instance",
            "resourceId": "i-8877665544332211",
            "configurationItemStatus": "OK",
            "configurationItemCaptureTime": "anytime",
            "tags":  tags,
            "configuration": {"iamInstanceProfile": iam_instance_profile_arn}
        }
    }
    return json.dumps(invoking_event)

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

def ssm_mock1():
    response = {
        "Patches": [
            {
                "Title": "2019-01 Security Update for Adobe Flash Player for Windows Server 2016 for x64-based Systems (KB4480979)",
                "KBId": "KB4480979",
                "Classification": "SecurityUpdates",
                "Severity": "Critical",
                "State": "Installed",
                "InstalledTime": 1546992000.0
            },
            {
                "Title": "",
                "KBId": "KB4481031",
                "Classification": "",
                "Severity": "",
                "State": "InstalledOther",
                "InstalledTime": 1549584000.0
            }
        ],
        "NextToken": "--token string truncated--"
    }
    SSM_CLIENT_MOCK.reset_mock(return_value=True)
    SSM_CLIENT_MOCK.describe_instance_patches = MagicMock(return_value=response)

def ssm_mock2():
    response = {
        "Patches": [
            {
                "Title": "2019-01 Security Update for Adobe Flash Player for Windows Server 2016 for x64-based Systems (KB4480979)",
                "KBId": "KB4480979",
                "Classification": "SecurityUpdates",
                "Severity": "Critical",
                "State": "Installed",
                "InstalledTime": 1546992000.0
            },
            {
                "Title": "",
                "KBId": "KB4481031",
                "Classification": "",
                "Severity": "",
                "State": "Missing",
                "InstalledTime": 1549584000.0
            }
        ],
        "NextToken": "--token string truncated--"
    }
    SSM_CLIENT_MOCK.reset_mock(return_value=True)
    SSM_CLIENT_MOCK.describe_instance_patches = MagicMock(return_value=response)

def ssm_mock3():
    response = {
        "Patches": [
            {
                "Title": "2019-01 Security Update for Adobe Flash Player for Windows Server 2016 for x64-based Systems (KB4480979)",
                "KBId": "KB4480979",
                "Classification": "SecurityUpdates",
                "Severity": "Critical",
                "State": "InstalledOther",
                "InstalledTime": 1546992000.0
            },
            {
                "Title": "",
                "KBId": "KB4481031",
                "Classification": "",
                "Severity": "",
                "State": "Failed",
                "InstalledTime": 1549584000.0
            }
        ],
        "NextToken": "--token string truncated--"
    }
    SSM_CLIENT_MOCK.reset_mock(return_value=True)
    SSM_CLIENT_MOCK.describe_instance_patches = MagicMock(return_value=response)
