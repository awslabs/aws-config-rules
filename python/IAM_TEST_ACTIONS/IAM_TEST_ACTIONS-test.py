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
import json

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::IAM::Role'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
iam_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'iam':
            return iam_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('IAM_TEST_ACTIONS')

class ComplianceTest(unittest.TestCase):
    invoking_event_default = '{\"configurationItem\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\",\"configurationItemCaptureTime\":\"2016-10-06T16:46:16.261Z\",\"awsAccountId\":\"123456789012\",\"configurationItemStatus\":\"OK\",\"resourceId\":\"AIDAICVB3PKAQMPEGDW2C\",\"resourceName\":\"somerolename\",\"configurationStateMd5Hash\":\"8f1ee69b297895a0f8bc5753eca68e96\",\"resourceCreationTime\":\"2016-10-06T16:46:10.489Z\",\"configurationStateId\":0,\"configurationItemVersion\":\"1.2\",\"ARN\":\"arn:aws:ec2:eu-west-1:123456789012:instance/i-00000000\",\"awsRegion\":\"eu-west-1\",\"availabilityZone\":\"eu-west-1\",\"resourceType\":\"AWS::IAM::Role\",\"tags\":{\"<Foo>\":\"<Bar>\"},\"relationships\":[{\"resourceId\":\"eipalloc-00000000\",\"resourceType\":\"AWS::IAM::Role\",\"name\":\"Is attached to ElasticIp\"}],\"configuration\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\"}},\"messageType\":\"ConfigurationItemChangeNotification\"}'
    rule_parameters_default = '{\"actions\":\"s3:GetObject,s3:PutObject\"}'

    invoking_event_permitted = '{\"configurationItem\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\",\"configurationItemCaptureTime\":\"2016-10-06T16:46:16.261Z\",\"awsAccountId\":\"123456789012\",\"configurationItemStatus\":\"OK\",\"resourceId\":\"AIDAICVB3PKAQMPEGDW2C\",\"resourceName\":\"somerolename\",\"configurationStateMd5Hash\":\"8f1ee69b297895a0f8bc5753eca68e96\",\"resourceCreationTime\":\"2016-10-06T16:46:10.489Z\",\"configurationStateId\":0,\"configurationItemVersion\":\"1.2\",\"ARN\":\"arn:aws:ec2:eu-west-1:123456789012:instance/i-00000000\",\"awsRegion\":\"eu-west-1\",\"availabilityZone\":\"eu-west-1\",\"resourceType\":\"AWS::IAM::Role\",\"tags\":{\"<Foo>\":\"<Bar>\"},\"relationships\":[{\"resourceId\":\"eipalloc-00000000\",\"resourceType\":\"AWS::IAM::Role\",\"name\":\"Is attached to ElasticIp\"}],\"configuration\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\"}},\"messageType\":\"ConfigurationItemChangeNotification\"}'
    
    invoking_event_permitted = '{\"configurationItem\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\",\"configurationItemCaptureTime\":\"2016-10-06T16:46:16.261Z\",\"awsAccountId\":\"123456789012\",\"configurationItemStatus\":\"OK\",\"resourceId\":\"AIDAICVB3PKAQMPEGDW2C\",\"resourceName\":\"somerolename\",\"configurationStateMd5Hash\":\"8f1ee69b297895a0f8bc5753eca68e96\",\"resourceCreationTime\":\"2016-10-06T16:46:10.489Z\",\"configurationStateId\":0,\"configurationItemVersion\":\"1.2\",\"ARN\":\"arn:aws:ec2:eu-west-1:123456789012:instance/i-00000000\",\"awsRegion\":\"eu-west-1\",\"availabilityZone\":\"eu-west-1\",\"resourceType\":\"AWS::IAM::Role\",\"tags\":{\"<Foo>\":\"<Bar>\"},\"relationships\":[{\"resourceId\":\"eipalloc-00000000\",\"resourceType\":\"AWS::IAM::Role\",\"name\":\"Is attached to ElasticIp\"}],\"configuration\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\"}},\"messageType\":\"ConfigurationItemChangeNotification\"}'
    rule_parameters_permitted_role = '{\"actions\":\"s3:GetObject,s3:PutObject\",\"permittedRoleNames\":\"somerolename\"}'

    invoking_event_compliant_with_resource = '{\"configurationItem\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\",\"configurationItemCaptureTime\":\"2016-10-06T16:46:16.261Z\",\"awsAccountId\":\"123456789012\",\"configurationItemStatus\":\"OK\",\"resourceId\":\"AIDAICVB3PKAQMPEGDW2C\",\"resourceName\":\"somerolename\",\"configurationStateMd5Hash\":\"8f1ee69b297895a0f8bc5753eca68e96\",\"resourceCreationTime\":\"2016-10-06T16:46:10.489Z\",\"configurationStateId\":0,\"configurationItemVersion\":\"1.2\",\"ARN\":\"arn:aws:ec2:eu-west-1:123456789012:instance/i-00000000\",\"awsRegion\":\"eu-west-1\",\"availabilityZone\":\"eu-west-1\",\"resourceType\":\"AWS::IAM::Role\",\"tags\":{\"<Foo>\":\"<Bar>\"},\"relationships\":[{\"resourceId\":\"eipalloc-00000000\",\"resourceType\":\"AWS::IAM::Role\",\"name\":\"Is attached to ElasticIp\"}],\"configuration\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\"}},\"messageType\":\"ConfigurationItemChangeNotification\"}'
    rule_parameters_with_resource = '{\"actions\":\"s3:GetObject,s3:PutObject\",\"resources\":\"aws:arn:s3:::bucketname,aws:arn:s3:::bucketname2\"}'

    invoking_event_compliant_sans_permitted = '{\"configurationItem\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\",\"configurationItemCaptureTime\":\"2016-10-06T16:46:16.261Z\",\"awsAccountId\":\"123456789012\",\"configurationItemStatus\":\"OK\",\"resourceId\":\"AIDAICVB3PKAQMPEGDW2C\",\"resourceName\":\"somerolename\",\"configurationStateMd5Hash\":\"8f1ee69b297895a0f8bc5753eca68e96\",\"resourceCreationTime\":\"2016-10-06T16:46:10.489Z\",\"configurationStateId\":0,\"configurationItemVersion\":\"1.2\",\"ARN\":\"arn:aws:ec2:eu-west-1:123456789012:instance/i-00000000\",\"awsRegion\":\"eu-west-1\",\"availabilityZone\":\"eu-west-1\",\"resourceType\":\"AWS::IAM::Role\",\"tags\":{\"<Foo>\":\"<Bar>\"},\"relationships\":[{\"resourceId\":\"eipalloc-00000000\",\"resourceType\":\"AWS::IAM::Role\",\"name\":\"Is attached to ElasticIp\"}],\"configuration\":{\"roleName\":\"somerolename\",\"arn\":\"arn:aws:iam::111122223333:role/somerolename\"}},\"messageType\":\"ConfigurationItemChangeNotification\"}'
    

    iam_get_role = {
        "Role": {
            "Path": "/",
            "RoleName": "somerolename",
            "RoleId": "AIDAICVB3PKAQMPEGDW2C",
            "Arn": "arn:aws:iam::111122223333:role/somerolename",
            "CreateDate": "2021-01-18T14:44:06+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::111122223333:root"
                        },
                        "Action": "sts:AssumeRole",
                    }
                ]
            },
            "MaxSessionDuration": 43200,
            "RoleLastUsed": {
                "LastUsedDate": "2021-03-01T15:48:03+00:00",
                "Region": "eu-west-1"
            }
        }
    }
    eval_with_allows_no_resource = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalResourceName": "*",
                "EvalDecision": "allowed",
                "MatchedStatements": [
                    {
                        "SourcePolicyId": "AdministratorAccess",
                        "SourcePolicyType": "IAM Policy",
                        "StartPosition": {
                            "Line": 3,
                            "Column": 17
                        },
                        "EndPosition": {
                            "Line": 8,
                            "Column": 6
                        }
                    }
                ],
                "MissingContextValues": []
            }
        ]
    }

    eval_with_allows_with_resource = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalResourceName": "arn:aws:s3:::bucket_name",
                "EvalDecision": "allowed",
                "MatchedStatements": [
                    {
                        "SourcePolicyId": "AdministratorAccess",
                        "SourcePolicyType": "IAM Policy",
                        "StartPosition": {
                            "Line": 3,
                            "Column": 17
                        },
                        "EndPosition": {
                            "Line": 8,
                            "Column": 6
                        }
                    }
                ],
                "MissingContextValues": []
            }
        ]
    }

    eval_implicit_deny_no_resource = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalResourceName": "*",
                "EvalDecision": "implicitDeny",
                "MatchedStatements": [],
                "MissingContextValues": []
            }
        ]
    }

    eval_implicit_deny_with_resource = {
        "EvaluationResults": [
            {
                "EvalActionName": "s3:GetObject",
                "EvalResourceName": "arn:aws:s3:::bucket_name",
                "EvalDecision": "implicitDeny",
                "MatchedStatements": [],
                "MissingContextValues": []
            }
        ]
    }
    
    def test_permitted_compliant(self):
        """
        Scenario 1:
        Given: IAM Role is the <permitted> list
        Then: Return COMPLIANT
        """
        lambda_event = build_lambda_configurationchange_event(invoking_event=self.invoking_event_permitted,rule_parameters=self.rule_parameters_permitted_role)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation="IAM Role is on Permitted List"))
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_no_resource_non_compliant(self):
        """
        Scenario 2:
        Given: IAM Role is not in the <permitted> list (or <permitted> is empty)
            And: The <resources> parameter is not set
            And: The policies attached to the IAM Role allow the Principal to apply one or more of the <actions> on the resources in general
        Then: Return NON_COMPLIANT
        """
        iam_client_mock.get_role = MagicMock(return_value=self.iam_get_role)
        iam_client_mock.simulate_principal_policy = MagicMock(return_value=self.eval_with_allows_no_resource)
        lambda_event = build_lambda_configurationchange_event(invoking_event=self.invoking_event_default,rule_parameters=self.rule_parameters_default)
        response = rule.lambda_handler(lambda_event, {})

        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation="A IAM Policy \"AdministratorAccess\" attached to the role allows s3:GetObject."))
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_no_resource_compliant(self):
        """
        Scenario 3:
        Given: IAM Role is not in the <permitted> list (or <permitted> is empty)
            And: The <resources> parameter is not set
            And: The policies attached to the IAM Role do not allow the Principal to apply one or more of the <actions> on the resources in general
        Then: Return COMPLIANT
        """
        iam_client_mock.get_role = MagicMock(return_value=self.iam_get_role)
        iam_client_mock.simulate_principal_policy = MagicMock(return_value=self.eval_implicit_deny_no_resource)
        lambda_event = build_lambda_configurationchange_event(invoking_event=self.invoking_event_default,rule_parameters=self.rule_parameters_default)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation="IAM Role is compliant"))
        assert_successful_evaluation(self, response, resp_expected)
    
    def test_resource_set_non_compliant(self):
        """
        Scenario 4:
        Given: IAM Role is not in the <permitted> list (or <permitted> is empty)
            And: The <resources> parameter is set
            And: The policies attached to the IAM Role allow the Principal to apply one or more of the <actions> on one or more of the <resources>
        Then: Return NON_COMPLIANT
        """
        iam_client_mock.get_role = MagicMock(return_value=self.iam_get_role)
        iam_client_mock.simulate_principal_policy = MagicMock(return_value=self.eval_with_allows_with_resource)
        lambda_event = build_lambda_configurationchange_event(invoking_event=self.invoking_event_compliant_with_resource,rule_parameters=self.rule_parameters_with_resource)
        response = rule.lambda_handler(lambda_event, {})

        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation="A IAM Policy \"AdministratorAccess\" attached to the role allows s3:GetObject."))
        assert_successful_evaluation(self, response, resp_expected)

    def test_resource_set_compliant(self):
        """
        Scenario 5:
        Given: IAM Role is not in the <permitted> list (or <permitted> is empty)
            And: The <resources> parameter is set
            And: The policies attached to the IAM Role do not allow the Principal to apply one or more of the <actions> on one or more of the <resources>
        Then: Return COMPLIANT
        """

        iam_client_mock.get_role = MagicMock(return_value=self.iam_get_role)
        iam_client_mock.simulate_principal_policy = MagicMock(return_value=self.eval_implicit_deny_with_resource)
        lambda_event = build_lambda_configurationchange_event(invoking_event=self.invoking_event_compliant_with_resource,rule_parameters=self.rule_parameters_with_resource)
        response = rule.lambda_handler(lambda_event, {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'AIDAICVB3PKAQMPEGDW2C', annotation="IAM Role is compliant"))
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
        'accountId': '111122223333',
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
        'accountId': '111122223333',
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
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
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
