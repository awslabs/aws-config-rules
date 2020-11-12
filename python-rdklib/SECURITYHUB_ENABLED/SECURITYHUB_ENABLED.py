"""
#####################################
##           Gherkin               ##
#####################################

Rule Name:
  SECURITYHUB_ENABLED

Description:
  Checks that AWS Security Hub is enabled for an AWS Account. The rule is NON_COMPLIANT if AWS Security Hub is not enabled.

Rationale:
   AWS Security Hub gives you a comprehensive view of your high-priority security alerts, and compliance status across AWS accounts.

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
    Given: SecurityHub is enabled for an AWS Account.
     Then: Return COMPLIANT

  Scenario: 2
    Given: SecurityHub is not enabled for an AWS Account.
     Then: Return NON_COMPLIANT

"""
import botocore
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

APPLICABLE_RESOURCES = ['AWS::::Account']

class SECURITYHUB_ENABLED(ConfigRule):

    # Set this to false to prevent unnecessary API calls
    delete_old_evaluations_on_scheduled_notification = False

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        client = client_factory.build_client('securityhub')
        evaluations = []
        try:
            security_hub_enabled = client.describe_hub()
            # Scenario:1 SecurityHub is enabled for an AWS Account.
            if security_hub_enabled:
                evaluations.append(Evaluation(ComplianceType.COMPLIANT, event['accountId'], APPLICABLE_RESOURCES[0]))
        except botocore.exceptions.ClientError as error:
            # Scenario:2 SecurityHub is not enabled for an AWS Account.
            if error.response['Error']['Code'] == 'InvalidAccessException':
                evaluations.append(Evaluation(ComplianceType.NON_COMPLIANT, event['accountId'], APPLICABLE_RESOURCES[0]))
            else:
                raise error
        return evaluations

def lambda_handler(event, context):
    my_rule = SECURITYHUB_ENABLED()
    evaluator = Evaluator(my_rule, APPLICABLE_RESOURCES)
    return evaluator.handle(event, context)
