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
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::RestApi'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()
apigw_client_mock = MagicMock()
vpc_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        elif client_name == 'apigateway':
            return apigw_client_mock
        elif client_name == 'ec2':
            return vpc_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('API_GW_PRIVATE_RESTRICTED')

class ComplianceTest(unittest.TestCase):

    #VPC descripion api call
    vpc_description = {
        "Vpcs": [
            {
                "VpcId": "vpc-7e934918"
            },
            {
                "VpcId": "vpc-3fd01559"
            }
        ]
    }

    vpc_endpoint_description = {
        "VpcEndpoints": [
            {
                "VpcEndpointId": "vpce-00174e7dff8fe43c1",
                "VpcId": "vpc-3fd01559"
            },
            {
                "VpcEndpointId": "vpce-03d70f31b65a06050",
                "VpcId": "vpc-3fd01559"
            }
        ]
    }

    apigw_in_regional_mode = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "REGIONAL"
                    ]
                },
                "name": "test-api-gateway"
            }
        ]
    }

    apigw_edge_optimized_mode = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "EDGE"
                    ]
                },
                "name": "test-api-gateway"
            }
        ]
    }

    apigw_no_policy_attached = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway"
            }
        ]
    }

    apigw_policy_has_no_allow_statement = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "id": "ck1phpk3ga",
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Deny\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":[\\\"execute-api:/*\\\"],\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}},{\\\"Effect\\\":\\\"Deny\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":[\\\"execute-api:/*\\\"],\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c2\\\"}}}]}"
            }
        ]
    }

    apigw_policy_without_proper_condition = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":[\\\"execute-api:/*\\\"],\\\"Condition\\\":{\\\"StringNotEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}},{\\\"Effect\\\":\\\"Deny\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":[\\\"execute-api:/*\\\"],\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c2\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_not_same_accout = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-00000000\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_endpoint_not_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00000000000000000\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_same_and_different_account_combination = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":[\\\"vpc-3fd01559\\\",\\\"vpc-00000000\\\"]}}}]}"
            }
        ]
    }

    apigw_vpc_endpoint_same_and_different_account_combination = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":[\\\"vpce-00000000000000000\\\",\\\"vpce-00174e7dff8fe43c1\\\"]}}}]}"
            }
        ]
    }

    apigw_vpc_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:ck1phpk3ga\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-3fd01559\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_endpoint_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:ck1phpk3ga\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}}]}"
            }
        ]
    }

    apigw_multiple_vpc_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":[\\\"vpc-3fd01559\\\",\\\"vpc-7e934918\\\"]}}}]}"
            }
        ]
    }

    apigw_multiple_vpc_endpoint_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":[\\\"vpce-03d70f31b65a06050\\\",\\\"vpce-00174e7dff8fe43c1\\\"]}}}]}"
            }
        ]
    }

    apigw_vpc_and_vpc_endpoint_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-3fd01559\\\",\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_and_vpc_endpoint_different_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "id": "apigwId",
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-00000000\\\",\\\"aws:sourceVpce\\\":\\\"vpce-00000000000000000\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_same_and_vpc_endpoint_different_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "id": "apigwId",
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-3fd01559\\\",\\\"aws:sourceVpce\\\":\\\"vpce-00000000000000000\\\"}}}]}"
            }
        ]
    }

    apigw_vpc_different_and_vpc_endpoint_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "id": "apigwId",
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-00000000\\\",\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}}]}"
            }
        ]
    }

    apigw_multiple_statement_same_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}},{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-3fd01559\\\"}}}]}"
            }
        ]
    }

    apigw_multiple_statement_different_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-0000000000000000\\\"}}},{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-00000000\\\"}}}]}"
            }
        ]
    }

    apigw_multiple_statement_one_different_account = {
        "items": [
            {
                "endpointConfiguration": {
                    "types": [
                        "PRIVATE"
                    ]
                },
                "name": "test-api-gateway",
                "policy": "{\\\"Version\\\":\\\"2012-10-17\\\",\\\"Statement\\\":[{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpce\\\":\\\"vpce-00174e7dff8fe43c1\\\"}}},{\\\"Effect\\\":\\\"Allow\\\",\\\"Principal\\\":\\\"*\\\",\\\"Action\\\":\\\"execute-api:Invoke\\\",\\\"Resource\\\":\\\"arn:aws:execute-api:us-west-2:123456789012:apigwId\\/*\\\",\\\"Condition\\\":{\\\"StringEquals\\\":{\\\"aws:sourceVpc\\\":\\\"vpc-00000000\\\"}}}]}"
            }
        ]
    }

    vpc_client_mock.describe_vpcs = MagicMock(return_value=vpc_description)
    vpc_client_mock.describe_vpc_endpoints = MagicMock(return_value=vpc_endpoint_description)

    #if apigw is regional - not-applicable
    def test_apigw_regional(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_in_regional_mode)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    #if apigw is edge optimized - not applicable
    def test_apigw_edge_optimized_mode(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_edge_optimized_mode)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NOT_APPLICABLE', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is private and has no policy attached to it = non-compliant
    def test_apigw_no_policy_attached(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_no_policy_attached)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'No resource policy is attached.'))
        assert_successful_evaluation(self, response, resp_expected)

    #private with policy attached and policy has no allow statement = non-compliant
    def test_apigw_no_allow_statement_in_policy(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_policy_has_no_allow_statement)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'This API has no resource policy with an Allow statement.'))
        assert_successful_evaluation(self, response, resp_expected)

    #gateway is privte and policy has allow statement and condition does not contain proper strmatch for VPC VPCE - non-compliant
    def test_apigw_policy_with_no_proper_condition(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_policy_without_proper_condition)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The Allow statement does not have VPC nor a VPCe.'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is prvate, has allow statement, has stringMatch for VPC/VPCE and VPC does not belong to same account - non compliant
    def test_apigw_vpc_not_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_not_same_accout)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is prvate, has allow statement, has stringMatch for VPC/VPCE and VPC Endpoint does not belong to same account - non compliant
    def test_apigw_vpc_endpoint_not_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_endpoint_not_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCEs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is prvate, has allow statement, has stringMatch for VPC/VPCE and one VPC beongs to same account and another one does not belong to same account - non compliant
    def test_apigw_vpc_same_and_different_account_combination(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_same_and_different_account_combination)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is prvate, has allow statement, has stringMatch for VPC/VPCE and one VPC Endpoint beongs to same account and another one does not belong to same account - non compliant
    def test_apigw_vpc_endpoint_same_and_different_account_combination(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_endpoint_same_and_different_account_combination)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCEs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is private and policy has allows statement with the condition allowing vpc from same vpc
    def test_apigw_vpc_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    # gateway is private and policy has allows statement with the condition allowing vpc-endpoint from same vpc
    def test_apigw_vpc_endpoint_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_endpoint_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    #gateway is private and policy has allow, condition contains string match for muliple vpc from same account
    def test_apigw_multiple_vpc_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_multiple_vpc_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    #gateway is private and policy has allow, condition contains string match for muliple vpc endpoint from same account
    def test_apigw_multiple_endpoint_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_multiple_vpc_endpoint_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_apigw_vpc_vpc_endpoint_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_and_vpc_endpoint_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_apigw_vpc_vpc_endpoint_different_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_and_vpc_endpoint_different_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCs are not in the same account than this API Gateway.'))
        print(response)
        assert_successful_evaluation(self, response, resp_expected)

    def test_apigw_vpc_same_vpc_endpoint_different_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_same_and_vpc_endpoint_different_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCEs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_apigw_vpc_different_vpc_endpoint_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_vpc_different_and_vpc_endpoint_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_apigw_multiple_statement_all_same_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_multiple_statement_same_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_apigw_multiple_statement_all_different_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_multiple_statement_different_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCEs are not in the same account than this API Gateway.'))
        assert_successful_evaluation(self, response, resp_expected)


    def test_apigw_multiple_statement_one_different_account(self):
        apigw_client_mock.get_rest_apis = MagicMock(return_value=self.apigw_multiple_statement_one_different_account)
        rule.ASSUME_ROLE_MODE = False
        response = rule.lambda_handler(build_lambda_scheduled_event(), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'test-api-gateway', 'AWS::ApiGateway::RestApi', 'The VPCs are not in the same account than this API Gateway.'))
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

     #commenting annotation mathcing, can be uncommented if you need to compare annotations
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertTrue(response[i]['OrderingTimestamp'])
     #commenting annotation mathcing, can be uncommented if you need to compare annotations
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
# Common Testing #
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
