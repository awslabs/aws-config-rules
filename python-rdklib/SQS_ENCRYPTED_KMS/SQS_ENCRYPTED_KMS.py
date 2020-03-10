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

"""
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  SQS_ENCRYPTED_KMS

Description:
  Check whether Amazon Simple Queue Service (Amazon SQS) is encrypted
  with AWS Key Management Service (AWS KMS).

Rationale:
  Encrypting gives the protection for the content of messages in Amazon SQS queues
  using keys managed in the AWS Key Management Service (AWS KMS).

Indicative Severity:
  Medium

Trigger:
  Configuration Change on AWS::SQS::Queue

Reports on:
  AWS::SQS::Queue

Scenarios:
  Scenario: 1
    Given: SQS Queue is active
      And: SQS Queue is encrypted with KMS key
     Then: Return COMPLIANT
  Scenario: 2
    Given: SQS Queue is active
      And: SQS Queue is not encrypted with KMS key
     Then: Return NON_COMPLIANT
"""

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType


class SQS_ENCRYPTED_KMS(ConfigRule):
    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):

        response = configuration_item.get('configuration').get('KmsMasterKeyId')

        if response is not None:
            return [Evaluation(ComplianceType.COMPLIANT)]

        return [Evaluation(ComplianceType.NON_COMPLIANT,
                           annotation="Enable KMS encryption for Amazon SQS queue")]


def lambda_handler(event, context):
    my_rule = SQS_ENCRYPTED_KMS()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
