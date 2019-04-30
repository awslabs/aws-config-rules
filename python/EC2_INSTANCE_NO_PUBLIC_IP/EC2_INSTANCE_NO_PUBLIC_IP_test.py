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
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::Instance'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EC2_INSTANCE_NO_PUBLIC_IP')

class ComplianceTest(unittest.TestCase):

    #Scenario 1 test cases: NON_COMPLIANT
    def test_scenario_1a_pri_eni_pri_ip_public(self):
        invoking_event_non_compliant = '{"configurationItem":{"configuration":{"networkInterfaces": [\
                                       {\
                                        "privateIpAddresses": [\
                                            {\
                                                "association": {\
                                                    "ipOwnerId": "amazon",\
                                                    "publicDnsName": "ec2-public-ip.region.compute.amazonaws.com",\
                                                    "publicIp": "public-ip"\
                                                },\
                                                "primary": "True",\
                                                "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                "privateIpAddress": "private-ip"\
                                            }\
                                        ]\
                                        }]},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::EC2::Instance","resourceId":"some-resource-id"},"messageType":"ConfigurationItemChangeNotification"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_non_compliant), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', 'AWS::EC2::Instance', 'This Amazon EC2 Instance uses a public IP.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_1b_pri_eni_sec_ip_public(self):
        invoking_event_non_compliant = '{"configurationItem":{"configuration":{"networkInterfaces": [\
                                        {\
                                            "privateIpAddresses": [\
                                                {\
                                                    "association": "None",\
                                                    "primary": "True",\
                                                    "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                    "privateIpAddress": "private-ip"\
                                                },\
                                                {\
                                                    "association": {\
                                                        "ipOwnerId": "account-id",\
                                                        "publicDnsName": "ec2-public-ip.region.compute.amazonaws.com",\
                                                        "publicIp": "public-ip"\
                                                    },\
                                                    "primary": "False",\
                                                    "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                    "privateIpAddress": "private-ip"\
                                                    }\
                                            ]\
                                        }]},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::EC2::Instance","resourceId":"some-resource-id"},"messageType":"ConfigurationItemChangeNotification"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_non_compliant), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', 'AWS::EC2::Instance', 'This Amazon EC2 Instance uses a public IP.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_1c_sec_eni_pri_ip_public(self):
        invoking_event_non_compliant = '{"configurationItem":{"configuration": {"networkInterfaces": [\
                                        {\
                                            "privateIpAddresses": [\
                                                {\
                                                    "association": {\
                                                        "ipOwnerId": "account-id",\
                                                        "publicDnsName": "ec2-public-ip.region.compute.amazonaws.com",\
                                                        "publicIp": "public-ip"\
                                                    },\
                                                    "primary": "True",\
                                                    "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                    "privateIpAddress": "private-ip"\
                                                }\
                                            ]\
                                        },\
                                        {\
                                            "privateIpAddresses": [\
                                                {\
                                                    "association": "None",\
                                                    "primary": "True",\
                                                    "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                    "privateIpAddress": "private-ip"\
                                                }\
                                            ]\
                                        }]},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::EC2::Instance","resourceId":"some-resource-id"},"messageType":"ConfigurationItemChangeNotification"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_non_compliant), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', 'AWS::EC2::Instance', 'This Amazon EC2 Instance uses a public IP.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_scenario_1d_sec_eni_sec_ip_public(self):
        invoking_event_non_compliant = '{"configurationItem":{"configuration": { "networkInterfaces": [\
                                    {\
                                        "privateIpAddresses": [\
                                                    {\
                                                        "association": "None",\
                                                        "primary": "True",\
                                                        "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                        "privateIpAddress": "private-ip"\
                                                    },\
                                                    {\
                                                        "association": {\
                                                            "ipOwnerId": "account-id",\
                                                            "publicDnsName": "ec2-public-ip.region.compute.amazonaws.com",\
                                                            "publicIp": "public-ip"\
                                                        },\
                                                        "primary": "False",\
                                                        "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                        "privateIpAddress": "private-ip"\
                                                    }\
                                        ]\
                                    },\
                                    { \
                                        "privateIpAddresses": [\
                                                    {\
                                                        "association": "None",\
                                                        "primary": "True",\
                                                        "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                        "privateIpAddress": "private-ip"\
                                                    },\
                                                    {\
                                                        "association": "None",\
                                                        "primary": "False",\
                                                        "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                        "privateIpAddress": "private-ip"\
                                                    }\
                                        ]\
                                    }]},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::EC2::Instance","resourceId":"some-resource-id"},"messageType":"ConfigurationItemChangeNotification"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_non_compliant), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'some-resource-id', 'AWS::EC2::Instance', 'This Amazon EC2 Instance uses a public IP.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 2 test case: COMPLIANT
    def test_scenario_2_no_public_ip(self):
        invoking_event_compliant = '{"configurationItem":{"configuration":{"networkInterfaces": [\
                                   {\
                                        "privateIpAddresses": [\
                                            {\
                                                "association": "None",\
                                                "primary": "True",\
                                                "privateDnsName": "ip-private-ip.region.compute.internal",\
                                                "privateIpAddress": "private-ip"\
                                            }\
                                        ]\
                                   }]},"configurationItemCaptureTime":"2018-07-02T03:37:52.418Z","awsAccountId":"123456789012","configurationItemStatus":"ResourceDiscovered","resourceType":"AWS::EC2::Instance","resourceId":"some-resource-id"},"messageType":"ConfigurationItemChangeNotification"}'
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event_compliant), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'some-resource-id', 'AWS::EC2::Instance'))
        assert_successful_evaluation(self, response, resp_expected)

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
