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

'''
#####################################
##           Gherkin               ##
#####################################

Rule Name:
  SECURITYHUB_ENABLED

Description:
  Checks whether SecurityHub is enabled. The rule is NON_COMPLIANT if SecurityHub is not enabled.

Rationale:
   AWS Security Hub gives you a comprehensive view of your high-priority security alerts,
   and compliance status across AWS accounts.

Indicative Severity:
  Medium

Trigger:
  Periodic

Reports on:
  AWS::::Account

Rule Parameters:
  None

Scenarios:
  Scenario: 1
    Given: SecurityHub is enabled.
     Then: Return COMPLIANT

  Scenario: 2
    Given: SecurityHub is not enabled.
     Then: Return NON_COMPLIANT with Annotation
'''

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

RESOURCE_TYPE = 'AWS::::Account'

class SECURITYHUB_ENABLED(ConfigRule):
    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        client = client_factory.build_client('securityhub')
        is_securityhub_enabled = True
        try:
            response = client.describe_hub()
        except:
            is_securityhub_enabled = False
        if is_securityhub_enabled:
            print('HubArn:' + response['HubArn'])
            print('SecurityHub Enabled.')
            return [Evaluation(ComplianceType.COMPLIANT, event['accountId'], RESOURCE_TYPE)]
        print('HubArn: None')
        print('SecurityHub NOT Enabled.')
        return [Evaluation(ComplianceType.NON_COMPLIANT, event['accountId'], RESOURCE_TYPE,
                           'AWS SecurityHub is not enabled.')]

def lambda_handler(event, context):
    my_rule = SECURITYHUB_ENABLED()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
