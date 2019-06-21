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
DEFAULT_RESOURCE_TYPE = 'AWS::EMR::Cluster'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
EMR_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        if client_name == 'emr':
            return EMR_CLIENT_MOCK
        raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('EMR_SECURITY_GROUPS_RESTRICTED')

class ComplianceTest(unittest.TestCase):

    cluster_list = {
        'Clusters': [{
            'Id': 'j-AAAAA0AAAAA',
            'Status': {
                'State': 'RUNNING'
            }
        }, {
            'Id': 'j-AAAAA000000',
            'Status': {
                'State': 'WAITING'
            }
        }, {
            'Id': 'j-AAAAA0BBBBB',
            'Status': {
                'State': 'RUNNING'
            }
        }]
    }

    described_clusters = [{
        "Cluster": {
            "Id": "j-AAAAA0AAAAA",
            "Ec2InstanceAttributes": {
                "EmrManagedMasterSecurityGroup": "sg-1111aaaa",
                "EmrManagedSlaveSecurityGroup": "sg-2222bbbb",
                "AdditionalMasterSecurityGroups": [],
                "AdditionalSlaveSecurityGroups": []
            }
        }
    }, {
        "Cluster": {
            "Id": "j-AAAAA000000",
            "Ec2InstanceAttributes": {
                "EmrManagedMasterSecurityGroup": "sg-3333cccc",
                "EmrManagedSlaveSecurityGroup": "sg-4444dddd",
                "AdditionalMasterSecurityGroups": [
                    "sg-1111aaaa"
                ],
                "AdditionalSlaveSecurityGroups": [
                    "sg-2222bbbb"
                ]
            }
        }
    }, {
        "Cluster": {
            "Id": "j-AAAAA0BBBBB",
            "Ec2InstanceAttributes": {
                "EmrManagedMasterSecurityGroup": "sg-1111aaaa",
                "EmrManagedSlaveSecurityGroup": "sg-2222bbbb",
                "AdditionalMasterSecurityGroups": [
                    "sg-3333cccc",
                    "sg-4444dddd"
                ],
                "AdditionalSlaveSecurityGroups": []
            }
        }
    }]

    #Scenario 1: No RUNNING and WAITING clusters
    def test_1_no_clusters(self):
        no_clusters = {
            "Clusters": []
        }
        EMR_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EMR_CLIENT_MOCK,
            "paginate.return_value": [no_clusters]})
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = [build_expected_response('NOT_APPLICABLE', compliance_resource_id='123456789012', compliance_resource_type="AWS::::Account")]
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 2: Security group(s) for the Amazon EMR cluster has a rule with IP range 0.0.0.0/0 or ::/0
    def test_2_security_groups_open(self):

        security_groups_config_items = {
            "baseConfigurationItems": [{
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"0.0.0.0/0\"}],\"ipv6Ranges\": []}],\"groupId\": \"sg-1111aaaa\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"1.1.1.1/32\"}],\"ipv6Ranges\": [{\"cidrIpv6\": \"::/0\"}]}],\"groupId\": \"sg-2222bbbb\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [],\"ipv6Ranges\": [{\"cidrIpv6\": \"::/0\"}]}],\"groupId\": \"sg-3333cccc\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"0.0.0.0/0\"}],\"ipv6Ranges\": [{\"cidrIpv6\": \"::/0\"}]}],\"groupId\": \"sg-4444dddd\"}"
            }],
            "unprocessedResourceKeys": []
        }

        EMR_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EMR_CLIENT_MOCK,
            "paginate.return_value": [self.cluster_list]})
        EMR_CLIENT_MOCK.describe_cluster = MagicMock(side_effect=self.described_clusters)
        CONFIG_CLIENT_MOCK.batch_get_resource_config = MagicMock(side_effect=[security_groups_config_items])

        resp_expected = [build_expected_response('NON_COMPLIANT', compliance_resource_id='j-AAAAA0AAAAA', annotation="This Amazon EMR cluster has one or more Security Groups open to the world."),
                         build_expected_response('NON_COMPLIANT', compliance_resource_id='j-AAAAA000000', annotation="This Amazon EMR cluster has one or more Security Groups open to the world."),
                         build_expected_response('NON_COMPLIANT', compliance_resource_id='j-AAAAA0BBBBB', annotation="This Amazon EMR cluster has one or more Security Groups open to the world.")]
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 3)

    #Scenario 3: Security group(s) for the Amazon EMR cluster do not have a rule with IP range 0.0.0.0/0 or ::/0
    def test_3_security_groups_closed(self):

        security_groups_config_items = {
            "baseConfigurationItems": [{
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"2.2.2.2/32\"}],\"ipv6Ranges\": []}],\"groupId\": \"sg-1111aaaa\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"1.1.1.1/32\"}],\"ipv6Ranges\": [{\"cidrIpv6\": \"1111:1111::/128\"}]}],\"groupId\": \"sg-2222bbbb\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [],\"ipv6Ranges\": [{\"cidrIpv6\": \"2222:2222::/128\"}]}],\"groupId\": \"sg-3333cccc\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"2.2.2.2/32\"}],\"ipv6Ranges\": [{\"cidrIpv6\": \"222:2222::/128\"}]}],\"groupId\": \"sg-4444dddd\"}"
            }],
            "unprocessedResourceKeys": []
        }

        EMR_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EMR_CLIENT_MOCK,
            "paginate.return_value": [self.cluster_list]})
        EMR_CLIENT_MOCK.describe_cluster = MagicMock(side_effect=self.described_clusters)
        CONFIG_CLIENT_MOCK.batch_get_resource_config = MagicMock(side_effect=[security_groups_config_items])

        resp_expected = [build_expected_response('COMPLIANT', compliance_resource_id='j-AAAAA0AAAAA'),
                         build_expected_response('COMPLIANT', compliance_resource_id='j-AAAAA000000'),
                         build_expected_response('COMPLIANT', compliance_resource_id='j-AAAAA0BBBBB')]
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 3)

    #Scenario 2 & 3 mixed
    def test_2_3_security_groups_mixed(self):

        security_groups_config_items = {
            "baseConfigurationItems": [{
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"2.2.2.2/32\"}],\"ipv6Ranges\": []}],\"groupId\": \"sg-1111aaaa\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"1.1.1.1/32\"}],\"ipv6Ranges\": [{\"cidrIpv6\": \"1111:1111::/128\"}]}],\"groupId\": \"sg-2222bbbb\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [],\"ipv6Ranges\": [{\"cidrIpv6\": \"::/0\"}]}],\"groupId\": \"sg-3333cccc\"}"
            }, {
                "configuration": "{\"ipPermissions\": [{\"ipv4Ranges\": [{\"cidrIp\": \"0.0.0.0/0\"}],\"ipv6Ranges\": [{\"cidrIpv6\": \"::/0\"}]}],\"groupId\": \"sg-4444dddd\"}"
            }],
            "unprocessedResourceKeys": []
        }

        EMR_CLIENT_MOCK.configure_mock(**{
            "get_paginator.return_value": EMR_CLIENT_MOCK,
            "paginate.return_value": [self.cluster_list]})
        EMR_CLIENT_MOCK.describe_cluster = MagicMock(side_effect=self.described_clusters)
        CONFIG_CLIENT_MOCK.batch_get_resource_config = MagicMock(side_effect=[security_groups_config_items])

        resp_expected = [build_expected_response('COMPLIANT', compliance_resource_id='j-AAAAA0AAAAA'),
                         build_expected_response('NON_COMPLIANT', compliance_resource_id='j-AAAAA000000', annotation="This Amazon EMR cluster has one or more Security Groups open to the world."),
                         build_expected_response('NON_COMPLIANT', compliance_resource_id='j-AAAAA0BBBBB', annotation="This Amazon EMR cluster has one or more Security Groups open to the world.")]
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        assert_successful_evaluation(self, response, resp_expected, 3)

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
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        RULE.evaluate_parameters = MagicMock(return_value=True)
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
