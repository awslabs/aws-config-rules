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
from rdklib import Evaluation, ComplianceType
import rdklibtest


MODULE = __import__('SQS_ENCRYPTED_KMS')
RULE = MODULE.SQS_ENCRYPTED_KMS()


class ComplianceTest(unittest.TestCase):

    def test_compliant(self):
        config_item = {"configuration": {"KmsMasterKeyId": "key"}}
        response = RULE.evaluate_change({}, {}, config_item, {})
        expected_response = [Evaluation(ComplianceType.COMPLIANT)]
        rdklibtest.assert_successful_evaluation(self, response, expected_response)

    def test_non_compliant(self):
        config_item = {"configuration": {}}
        response = RULE.evaluate_change({}, {}, config_item, {})
        expected_response = [Evaluation(ComplianceType.NON_COMPLIANT,
                                        annotation="Enable KMS encryption for Amazon SQS queue")]
        rdklibtest.assert_successful_evaluation(self, response, expected_response)
