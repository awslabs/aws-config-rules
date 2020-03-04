# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import unittest
from mock import patch, MagicMock
# from botocore.exceptions import ClientError
# import rdklib
from rdklib import Evaluation, ComplianceType
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::::Account'

#############
# Main Code #
#############

MODULE = __import__('SECURITYHUB_ENABLED')
RULE = MODULE.SECURITYHUB_ENABLED()

CLIENT_FACTORY = MagicMock()

SECURITYHUB_CLIENT_MOCK = MagicMock()

MOCK_SECURITYHUB_ENABLED = {
    "HubArn": "arn:aws:securityhub:ap-southeast-1:632747342146:hub/default",
    "SubscribedAt": "2020-03-03T04:54:41.610Z"
    }

MOCK_EVENT = {
    "accountId": "632747342146"
    }

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 'securityhub':
        return SECURITYHUB_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

def my_side_effect():
    raise Exception("An error occurred (InvalidAccessException) when calling the DescribeHub operation: AccountId: 632747342146 is not enabled for securityhub. Currentstate: false")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    def test_evaluate_periodic_1_compliant(self):
        SECURITYHUB_CLIENT_MOCK.describe_hub.return_value = MOCK_SECURITYHUB_ENABLED
        response = RULE.evaluate_periodic(MOCK_EVENT, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, '632747342146', RESOURCE_TYPE)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)

    def test_evaluate_periodic_2_non_compliant(self):
        SECURITYHUB_CLIENT_MOCK.describe_hub.side_effect = my_side_effect
        response = RULE.evaluate_periodic(MOCK_EVENT, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, '632747342146', RESOURCE_TYPE, 'AWS SecurityHub is not enabled.')
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, 1)
