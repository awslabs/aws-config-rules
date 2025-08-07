# Copyright 2017-2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
import botocore
import unittest
from unittest.mock import MagicMock, patch

from rdklib import ComplianceType, Evaluation
from rdklibtest import assert_successful_evaluation

# Define the default resource to report to Config Rules
RESOURCE_TYPE = "AWS::IAM::User"

#############
# Main Code #
#############

CLIENT_FACTORY = MagicMock()
IAM_CLIENT_MOCK = MagicMock()
IAM_USER_PAGINATOR_MOCK = MagicMock()

MODULE = __import__("IAM_USER_NO_SERVICE_SPECIFIC_CREDENTIALS")
RULE = MODULE.IAM_USER_NO_SERVICE_SPECIFIC_CREDENTIALS()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == "iam":
        return IAM_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")


def mock_evaluator_handle(event, context):
    return f"Event: {event} - Context: {context}"


@patch.object(CLIENT_FACTORY, "build_client", MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):
    COMPLIANT_USER_ID = 'compliant_user_id'
    MATCHING_SERVICE_NAME = 'matchingService'
    MATCHING_CREDENTIAL_ID = 'matchingCredential'
    NON_COMPLIANT_USER_ID = 'non_compliant_user_id'
    NON_MATCHING_SERVICE_NAME = 'nonMatchingService'
    NON_MATCHING_CREDENTIAL_ID = 'nonMatchingCredential'
    PARAMETERS = { 'ServiceName': MATCHING_SERVICE_NAME }

    CLIENT_ERROR = botocore.exceptions.ClientError({
        'Error': {
            'Code': 'unknown-code', 
            'Message': 'unknown-message'
            }
        }, 
        'operation'
    )

    ### IAM.list_users mock response
    user_page_empty = [ {  "Users": [ ] } ]
    user_page_expect_compliant = [ {  "Users": [ { "UserName": "NAME",  "UserId": COMPLIANT_USER_ID } ] } ]
    user_page_expect_non_compliant = [ {  "Users": [ { "UserName": "NAME",  "UserId": NON_COMPLIANT_USER_ID } ] } ]


    ### IAM.list_service_specific_credentials mock responses
    no_service_specific_credentials = { 'ServiceSpecificCredentials': [], 'IsTruncated': False }
    service_specific_credentials_active = { 
        'ServiceSpecificCredentials': [
            {
                'Status': 'Active',
                'ServiceSpecificCredentialId': MATCHING_CREDENTIAL_ID,
                'ServiceName': MATCHING_SERVICE_NAME
            }
        ],
        'IsTruncated': False
    }
    service_specific_credentials_active_page_one = { 
        'ServiceSpecificCredentials': [
            {
                'Status': 'Active',
                'ServiceSpecificCredentialId': MATCHING_CREDENTIAL_ID,
                'ServiceName': MATCHING_SERVICE_NAME
            }
        ],
        'IsTruncated': True,
        'Marker': 'getPageTwo'
    }
    service_specific_credentials_inactive_page_one = { 
        'ServiceSpecificCredentials': [
            {
                'Status': 'NotActive',
                'ServiceSpecificCredentialId': NON_MATCHING_CREDENTIAL_ID,
                'ServiceName': MATCHING_SERVICE_NAME
            }
        ],
        'IsTruncated': True,
        'Marker': 'getPageTwo'
    }
    service_specific_credentials_active_page_two = { 
        'ServiceSpecificCredentials': [
            {
                'Status': 'Active',
                'ServiceSpecificCredentialId': MATCHING_CREDENTIAL_ID,
                'ServiceName': MATCHING_SERVICE_NAME
            }
        ],
        'IsTruncated': False
    }
    service_specific_credentials_inactive = { 
        'ServiceSpecificCredentials': [
            {
                'Status': 'NotActive',
                'ServiceSpecificCredentialId': MATCHING_CREDENTIAL_ID,
                'ServiceName': MATCHING_SERVICE_NAME
            }
        ],
        'IsTruncated': False
    }


    def setUp(self):
        IAM_CLIENT_MOCK.reset_mock(return_value=True, side_effect=True)
        IAM_CLIENT_MOCK.get_paginator.return_value = IAM_USER_PAGINATOR_MOCK


    # Scenario 1 - Returns Empty if no IAM Users
    def test_scenario1_no_iam_users_returns_empty(self):
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_empty
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        self.assertEqual(response, [])


    # Scenario 2: No ServiceSpecific credentials attached
    def test_scenario2_no_sscredentials_returns_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.return_value = self.no_service_specific_credentials
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        response_expected = [
            Evaluation(
                ComplianceType.COMPLIANT,
                resourceId=self.COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation='No active ServiceSpecific credentials found'
            )]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 3: Inactive SSCreds - no parameter
    def test_scenario3_sscredentials_inactive_returns_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.return_value = self.service_specific_credentials_inactive
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        response_expected = [
            Evaluation(
                ComplianceType.COMPLIANT,
                resourceId=self.COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation='No active ServiceSpecific credentials found'
            )]
        assert_successful_evaluation(self, response, response_expected)

    # Scenario 4: Inactive SSCreds - parameter matches
    def test_scenario4_sscredentials_matching_inactive_returns_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.return_value = self.service_specific_credentials_inactive
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, self.PARAMETERS)
        response_expected = [
            Evaluation(
                ComplianceType.COMPLIANT,
                resourceId=self.COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation='No active ServiceSpecific credentials found'
            )]
        assert_successful_evaluation(self, response, response_expected)


    # Scenario 5: Active SSCreds - parameter does not match
    def test_scenario5_sscredentials_not_matching_returns_compliant(self):
        ## Assumption: No SSCreds for the ServiceName filter from parameters
        ##      so iam.list_service_specific_credentials returns empty list
        IAM_CLIENT_MOCK.list_service_specific_credentials.return_value = self.no_service_specific_credentials
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, self.PARAMETERS)
        response_expected = [
            Evaluation(
                ComplianceType.COMPLIANT,
                resourceId=self.COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation='No active ServiceSpecific credentials found'
            )]
        assert_successful_evaluation(self, response, response_expected)


    # Scenario 6: Active SSCreds - no parameters
    def test_scenario6_sscredentials_active_returns_non_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.return_value = self.service_specific_credentials_active
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_non_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        response_expected = [
            Evaluation(
                ComplianceType.NON_COMPLIANT,
                resourceId=self.NON_COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation=f'Active service specific credential found: {self.MATCHING_CREDENTIAL_ID}'
            )]
        assert_successful_evaluation(self, response, response_expected)
    
    # Scenario 6: Active SSCreds - paginated, active cred on page 2
    def test_scenario6_sscredentials_paginated_active_page_two_returns_non_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.side_effect = [
            self.service_specific_credentials_inactive_page_one,
            self.service_specific_credentials_active_page_two
        ]
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_non_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        response_expected = [
            Evaluation(
                ComplianceType.NON_COMPLIANT,
                resourceId=self.NON_COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation=f'Active service specific credential found: {self.MATCHING_CREDENTIAL_ID}'
            )]
        assert_successful_evaluation(self, response, response_expected)
        assert IAM_CLIENT_MOCK.list_service_specific_credentials.call_count == 2

    # Scenario 6: Active SSCreds - paginated, active cred on page 1
    def test_scenario6_sscredentials_paginated_active_page_two_returns_non_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.side_effect = [
            self.service_specific_credentials_active_page_one,
            self.service_specific_credentials_active_page_two
        ]
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_non_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        response_expected = [
            Evaluation(
                ComplianceType.NON_COMPLIANT,
                resourceId=self.NON_COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation=f'Active service specific credential found: {self.MATCHING_CREDENTIAL_ID}'
            )]
        assert_successful_evaluation(self, response, response_expected)
        assert IAM_CLIENT_MOCK.list_service_specific_credentials.call_count == 1

    # Scenario 7: Active SSCreds - serviceName matches parameter
    def test_scenario7_sscredentials_matching_active_returns_non_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials.return_value = self.service_specific_credentials_active
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_non_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, self.PARAMETERS)
        response_expected = [
            Evaluation(
                ComplianceType.NON_COMPLIANT,
                resourceId=self.NON_COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation=f'Active service specific credential found: {self.MATCHING_CREDENTIAL_ID}'
            )]
        assert_successful_evaluation(self, response, response_expected)


    # Scenario 8: Error calling list_service_specific_credentials
    def test_scenario8_listSSCreds_error_returns_non_compliant(self):
        IAM_CLIENT_MOCK.list_service_specific_credentials = MagicMock(side_effect=self.CLIENT_ERROR)
        IAM_USER_PAGINATOR_MOCK.paginate.return_value = self.user_page_expect_compliant

        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        response_expected = [
            Evaluation(
                ComplianceType.NON_COMPLIANT,
                resourceId=self.COMPLIANT_USER_ID,
                resourceType=RESOURCE_TYPE,
                annotation=f'Encountered error checking credentials. Check custom rule lambda logs'
            )]
        assert_successful_evaluation(self, response, response_expected)


    # Scenario 9: Error calling list_service_specific_credentials
    def test_scenario9_listUsers_error_raises_ex(self):
        IAM_USER_PAGINATOR_MOCK.paginate = MagicMock(side_effect=self.CLIENT_ERROR)
        try:
            response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
            self.assertTrue(False)
        except Exception as e:
            self.assertEqual(e, self.CLIENT_ERROR)
    

    # No scenario lambda handler passed an event and context
    @patch.object(MODULE.Evaluator, "handle", side_effect=mock_evaluator_handle)
    def test_lambda_handler_called_with_event_and_context(self, mock_evaluator):
        response = MODULE.lambda_handler("event", "context")
        response_expected = "Event: event - Context: context"
        self.assertEqual(response, response_expected)
