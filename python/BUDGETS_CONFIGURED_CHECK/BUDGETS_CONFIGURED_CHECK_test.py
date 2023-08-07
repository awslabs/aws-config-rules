import sys
import unittest
from unittest.mock import MagicMock
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = "AWS::Budgets::Budget"

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
BUDGETS_CLIENT_MOCK = MagicMock()


class Boto3Mock:
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == "config":
            return CONFIG_CLIENT_MOCK
        if client_name == "sts":
            return STS_CLIENT_MOCK
        if client_name == "budgets":
            return BUDGETS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")


sys.modules["boto3"] = Boto3Mock()

RULE = __import__("BUDGETS_CONFIGURED_CHECK")


class ComplianceTest(unittest.TestCase):

    rule_parameters = '{"SomeParameterKey":"SomeParameterValue","SomeParameterKey2":"SomeParameterValue2"}'

    invoking_event_iam_role_sample = '{"configurationItem":{"relatedEvents":[],"relationships":[],"configuration":{},"tags":{},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::IAM::Role","resourceId":"some-resource-id","resourceName":"some-resource-name","ARN":"some-arn"},"notificationCreationTime":"2018-07-02T23:05:34.445Z","messageType":"ConfigurationItemChangeNotification"}'

    def setUp(self):
        pass

    def test_scenario_1_none_compliant_resources(self):
        describe_budgets_result = {}
        expected_response = [
            build_expected_response(
                compliance_type='NON_COMPLIANT',
                compliance_resource_id='123456789012',
                annotation='This Account has no AWS Budgets configured.'
            )
        ]

        BUDGETS_CLIENT_MOCK.describe_budgets = MagicMock(return_value=describe_budgets_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        print(response)
        assert_successful_evaluation(self, response, expected_response, len(response))


    def test_scenario_2_none_compliant_resources(self):
        describe_budgets_result = {
            'Budgets': [
                {
                    'BudgetType': 'SAVINGS_PLANS_COVERAGE'
                }
            ]
        }
        expected_response = [
            build_expected_response(
                compliance_type='NON_COMPLIANT',
                compliance_resource_id='123456789012',
                annotation='This Account has no AWS Budgets configured.'
            )
        ]

        BUDGETS_CLIENT_MOCK.describe_budgets = MagicMock(return_value=describe_budgets_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        print(response)
        assert_successful_evaluation(self, response, expected_response, len(response))


    def test_scenario_3_compliant_resources(self):
        describe_budgets_result = {
            'Budgets': [
                {
                    'BudgetType': 'COST'
                }
            ]
        }
        expected_response = [
            build_expected_response(
                compliance_type='NOT_APPLICABLE',
                compliance_resource_id='123456789012'
            )
        ]

        BUDGETS_CLIENT_MOCK.describe_budgets = MagicMock(return_value=describe_budgets_result)
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        print(response)
        assert_successful_evaluation(self, response, expected_response, len(response))

####################
# Helper Functions #
####################

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        "configRuleName": "BUDGETS_CONFIGURED_CHECK",
        "executionRoleArn": "roleArn",
        "eventLeftScope": False,
        "invokingEvent": invoking_event,
        "accountId": "123456789012",
        "configRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/BUDGETS_CONFIGURED_CHECK-8fngan",
        "resultToken": "token",
    }
    if rule_parameters:
        event_to_return["ruleParameters"] = rule_parameters
    return event_to_return


def build_expected_response(
    compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None
):
    if not annotation:
        return {
            "ComplianceType": compliance_type,
            "ComplianceResourceId": compliance_resource_id,
            "ComplianceResourceType": compliance_resource_type,
        }
    return {
        "ComplianceType": compliance_type,
        "ComplianceResourceId": compliance_resource_id,
        "ComplianceResourceType": compliance_resource_type,
        "Annotation": annotation,
    }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected["ComplianceResourceType"], response["ComplianceResourceType"])
        test_class.assertEquals(resp_expected["ComplianceResourceId"], response["ComplianceResourceId"])
        test_class.assertEquals(resp_expected["ComplianceType"], response["ComplianceType"])
        test_class.assertTrue(response["OrderingTimestamp"])
        if "Annotation" in resp_expected or "Annotation" in response:
            test_class.assertEquals(resp_expected["Annotation"], response["Annotation"])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected["ComplianceResourceType"], response[i]["ComplianceResourceType"])
            test_class.assertEquals(response_expected["ComplianceResourceId"], response[i]["ComplianceResourceId"])
            test_class.assertEquals(response_expected["ComplianceType"], response[i]["ComplianceType"])
            test_class.assertTrue(response[i]["OrderingTimestamp"])
            if "Annotation" in response_expected or "Annotation" in response[i]:
                test_class.assertEquals(response_expected["Annotation"], response[i]["Annotation"])
