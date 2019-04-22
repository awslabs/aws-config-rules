#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#
import sys
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EMR::Cluster'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
emr_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        if client_name == 'emr':
            return emr_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('EMR_KERBEROS_ENABLED')

class TestInvalidCustomerInput(unittest.TestCase):
    def setUp(self):
        config_client_mock.reset_mock()
        config_client_mock.put_evaluations = MagicMock(
            return_value="{'FailedEvaluations': [{'ComplianceResourceType': 'string','ComplianceResourceId': 'string','ComplianceType': 'string','Annotation': 'string','OrderingTimestamp': datetime(2015, 1, 1)}]}")
        emr_client_mock.list_clusters = MagicMock(return_value={'Clusters': [{'Id': 'j-AAAAA0AAAAA'}]})

    def test_CustomerInput_TicketLifetimeInHours_InvalidValue(self):
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"NotExpectedvalue"}'),
                                       {})
        print(response)
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

    def test_CustomerInput_Realm_InvalidValue(self):
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"Realm":"NotExpectedvalue"}'), {})
        print(response)
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

    def test_CustomerInput_Domain_InvalidValue(self):
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"Domain":"NotExpectedvalue"}'), {})
        print(response)
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

    def test_CustomerInput_AdminServer_InvalidValue(self):
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"AdminServer":"NotExpectedvalue"}'), {})
        print(response)
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

    def test_CustomerInput_KdcServer_InvalidValue(self):
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"KdcServer":"NotExpectedvalue"}'), {})
        print(response)
        self.assertEqual(response['customerErrorCode'], 'InvalidParameterValueException')

class TestConfiguration(unittest.TestCase):
    putevaluation_not_applicable = [{'ComplianceType': 'NOT_APPLICABLE', 'ComplianceResourceType': 'AWS::EMR::Cluster',
                                     'ComplianceResourceId': 'j-AAAAA0AAAAA', 'OrderingTimestamp': 'datetime'}]
    putevaluation_compliant_noclusters = [{'ComplianceType': 'COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
                                           'ComplianceResourceId': 'None', 'Annotation': 'No Cluster detected.',
                                           'OrderingTimestamp': 'datetime'}]
    putevaluation_compliant = [{'ComplianceType': 'COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
                                'ComplianceResourceId': 'j-AAAAA0AAAAA', 'Annotation': 'No Cluster detected.',
                                'OrderingTimestamp': 'datetime'}]
    putevaluation_compliant_valid = [{'ComplianceType': 'COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
                                      'ComplianceResourceId': 'j-AAAAA0AAAAA',
                                      'Annotation': 'This EMR cluster is properly Kerberos Enabled.',
                                      'OrderingTimestamp': 'datetime'
                                      }]
    putevaluation_non_compliant = [{'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
                                    'ComplianceResourceId': 'j-AAAAA0AAAAA',
                                    'Annotation': 'No Security Configuration is attached.',
                                    'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_sc_ticketlifetimeinvalid = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'TicketLifetimeInHours is smaller than the specified Rule parameter TicketLifetimeInHours.',
         'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_nocrossrealm = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'CrossRealmTrustConfiguration is not configured in security configuration.',
         'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_noauthconfig = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'Kerberos Authentication is not enabled in the Security Configuration.',
         'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_realm_invalid = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'Realm is not equal to the specified Rule parameter Realm.', 'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_domain_invalid = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'Domain is not equal to the specified Rule parameter Domain.', 'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_adminserver_invalid = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'AdminServer is not equal to the specified Rule parameter AdminServer.',
         'OrderingTimestamp': 'datetime'}]
    putevaluation_non_compliant_kdcserver_invalid = [
        {'ComplianceType': 'NON_COMPLIANT', 'ComplianceResourceType': 'AWS::EMR::Cluster',
         'ComplianceResourceId': 'j-AAAAA0AAAAA',
         'Annotation': 'KdcServer is not equal to the specified Rule parameter KdcServer.',
         'OrderingTimestamp': 'datetime'}]

    listclusters_empty = {'Clusters': []}
    listclusters_valid = {'Clusters': [{'Id': 'j-AAAAA0AAAAA'}]}
    listclusters_valid_running = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'RUNNING'}}]}
    listclusters_valid_terminating = {'Clusters': [{'Id': 'j-AAAAA0AAAAA', 'Status': {'State': 'TERMINATING'}}]}

    describedcluster_state_terminating = {'Cluster': {'Status': {'State': 'TERMINATING'}}}
    describedcluster_state_terminated = {'Cluster': {'Status': {'State': 'TERMINATED'}}}
    describedcluster_state_terminatedwitherror = {'Cluster': {'Status': {'State': 'TERMINATED_WITH_ERRORS'}}}
    describedcluster_state_waiting = {'Cluster': {'Status': {'State': 'WAITING'}}}
    describedcluster_state_running_noSC = {'Cluster': {'Status': {'State': 'RUNNING'}}}
    describedcluster_state_running_sc = {'Cluster': {'Status': {'State': 'RUNNING'}, 'SecurityConfiguration': 'SCid'}}

    describedsc_TicketLifetimeInHours_non_compliant = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "21"}}}}'}
    describedsc_nocrossrealm_non_compliant = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"Provider": "ClusterDedicatedKdc","ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "24"}}}}'}
    describedsc_noauthconfig_non_compliant = {
        "SecurityConfiguration": '{"EncryptionConfiguration":{"EnableInTransitEncryption":"false","EnableAtRestEncryption":"false"}}'}
    describedsc_non_compliant_realm_invalid = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"Provider": "ClusterDedicatedKdc","ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "24","CrossRealmTrustConfiguration":{"Realm": "WW.DOMAIN.COM","Domain": "ad.domain.com","AdminServer": "ad.domain.com","KdcServer": "ad.domain.com"}}}}}'}
    describedsc_non_compliant_domain_invalid = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"Provider": "ClusterDedicatedKdc","ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "24","CrossRealmTrustConfiguration":{"Realm": "AD.DOMAIN.COM","Domain": "ww.domain.com","AdminServer": "ad.domain.com","KdcServer": "ad.domain.com"}}}}}'}
    describedsc_non_compliant_adminserver_invalid = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"Provider": "ClusterDedicatedKdc","ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "24","CrossRealmTrustConfiguration":{"Realm": "AD.DOMAIN.COM","Domain": "ad.domain.com","AdminServer": "ww.domain.com","KdcServer": "ad.domain.com"}}}}}'}
    describedsc_non_compliant_kdcserver_invalid = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"Provider": "ClusterDedicatedKdc","ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "24","CrossRealmTrustConfiguration":{"Realm": "AD.DOMAIN.COM","Domain": "ad.domain.com","AdminServer": "ad.domain.com","KdcServer": "ww.domain.com"}}}}}'}
    describedsc_compliant_all_valid = {
        "SecurityConfiguration": '{"AuthenticationConfiguration": {"KerberosConfiguration": {"Provider": "ClusterDedicatedKdc","ClusterDedicatedKdcConfiguration": {"TicketLifetimeInHours": "24","CrossRealmTrustConfiguration":{"Realm": "AD.DOMAIN.COM","Domain": "ad.domain.com","AdminServer": "ad.domain.com","KdcServer": "ad.domain.com"}}}}}'}

    def setUp(self):
        config_client_mock.reset_mock()

    def test_customer_emr_ListClusters_api_error(self):
        emr_client_mock.list_clusters = MagicMock(
            side_effect=botocore.exceptions.ClientError({'Error': {'Code': '400', 'Message': 'PermissionDenied'}},
                                                        'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        print(response)
        self.assertEqual(response['customerErrorCode'], '400')

    def test_service_emr_ListClusters_api_error(self):
        emr_client_mock.list_clusters = MagicMock(
            side_effect=botocore.exceptions.ClientError({'Error': {'Code': '500', 'Message': 'service-error'}},
                                                        'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        self.assertEqual(response['customerErrorCode'], 'InternalError')

    def test_customer_emr_DescribeCluster_api_error(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(
            side_effect=botocore.exceptions.ClientError({'Error': {'Code': '400', 'Message': 'PermissionDenied'}},
                                                        'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        self.assertEqual(response['customerErrorCode'], '400')

    def test_service_emr_DescribeCluster_api_error(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(
            side_effect=botocore.exceptions.ClientError({'Error': {'Code': '500', 'Message': 'service-error'}},
                                                        'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        self.assertEqual(response['customerErrorCode'], 'InternalError')

    def test_customer_emr_DescribeSecurityConfiguration_api_error(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            side_effect=botocore.exceptions.ClientError({'Error': {'Code': '400', 'Message': 'PermissionDenied'}},
                                                        'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        self.assertEqual(response['customerErrorCode'], '400')

    def test_service_emr_DescribeSecurityConfiguration_api_error(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            side_effect=botocore.exceptions.ClientError({'Error': {'Code': '500', 'Message': 'service-error'}},
                                                        'operation'))
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        self.assertEqual(response['customerErrorCode'], 'InternalError')

    def test_Compliant_NoCluster(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_empty)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_compliant_noclusters)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        print(response)
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceId': '123456789012',
            'ComplianceResourceType': 'AWS::::Account'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonApplicable_Cluster_Terminated(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid_terminating)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_terminated)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_not_applicable)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        print(response)
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'ComplianceResourceType': 'AWS::EMR::Cluster'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonApplicable_Cluster_Terminating(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid_terminating)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_terminating)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NOT_APPLICABLE',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'ComplianceResourceType': 'AWS::EMR::Cluster'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_NoSecurityConfig(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_noSC)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'No Security Configuration is attached.'
        })
        print(response)
        print(resp_expected)
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_TicketLifetimeInHours_InvalidValue(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_TicketLifetimeInHours_non_compliant)
        config_client_mock.put_evaluations = MagicMock(
            return_value=self.putevaluation_non_compliant_sc_ticketlifetimeinvalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24"}'), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'TicketLifetimeInHours is smaller than the specified Rule parameter TicketLifetimeInHours.'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_NoCrossRealm_RuleParamsPresent(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_nocrossrealm_non_compliant)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_non_compliant_nocrossrealm)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24"}'), {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'CrossRealmTrustConfiguration is not configured in security configuration.'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_NoAuthConfig(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_noauthconfig_non_compliant)
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'j-AAAAA0AAAAA', annotation='Kerberos Authentication is not enabled in the Security Configuration.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_Realm_invalid(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_non_compliant_realm_invalid)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_non_compliant_realm_invalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24","Realm":"AD.DOMAIN.COM","Domain":"ad.domain.com","AdminServer":"ad.domain.com","KdcServer":"ad.domain.com"}'),
            {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'Realm is not equal to the specified Rule parameter Realm.',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_Domain_invalid(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_non_compliant_domain_invalid)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_non_compliant_domain_invalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24","Realm":"AD.DOMAIN.COM","Domain":"ad.domain.com","AdminServer":"ad.domain.com","KdcServer":"ad.domain.com"}'),
            {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'Domain is not equal to the specified Rule parameter Domain.',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_AdminServer_invalid(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_non_compliant_adminserver_invalid)
        config_client_mock.put_evaluations = MagicMock(
            return_value=self.putevaluation_non_compliant_adminserver_invalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24","Realm":"AD.DOMAIN.COM","Domain":"ad.domain.com","AdminServer":"ad.domain.com","KdcServer":"ad.domain.com"}'),
            {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'AdminServer is not equal to the specified Rule parameter AdminServer.',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_NonCompliant_Cluster_SecurityConfig_KdcServer_invalid(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(
            return_value=self.describedsc_non_compliant_kdcserver_invalid)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_non_compliant_kdcserver_invalid)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24","Realm":"AD.DOMAIN.COM","Domain":"ad.domain.com","AdminServer":"ad.domain.com","KdcServer":"ad.domain.com"}'),
            {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'NON_COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA',
            'Annotation': 'KdcServer is not equal to the specified Rule parameter KdcServer.',
            'OrderingTimestamp': 'datetime'
        })
        assert_successful_evaluation(self, response, resp_expected)

    def test_Compliant_Cluster_SecurityConfig_AllRuleParams_valid(self):
        emr_client_mock.list_clusters = MagicMock(return_value=self.listclusters_valid)
        emr_client_mock.describe_cluster = MagicMock(return_value=self.describedcluster_state_running_sc)
        emr_client_mock.describe_security_configuration = MagicMock(return_value=self.describedsc_compliant_all_valid)
        config_client_mock.put_evaluations = MagicMock(return_value=self.putevaluation_compliant_valid)
        response = rule.lambda_handler(build_lambda_scheduled_event(rule_parameters='{"TicketLifetimeInHours":"24","Realm":"AD.DOMAIN.COM","Domain":"ad.domain.com","AdminServer":"ad.domain.com","KdcServer":"ad.domain.com"}'),
            {})
        resp_expected = []
        resp_expected.append({
            'ComplianceType': 'COMPLIANT',
            'ComplianceResourceType': 'AWS::EMR::Cluster',
            'ComplianceResourceId': 'j-AAAAA0AAAAA'
        })
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

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
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
# Commun Testing #
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