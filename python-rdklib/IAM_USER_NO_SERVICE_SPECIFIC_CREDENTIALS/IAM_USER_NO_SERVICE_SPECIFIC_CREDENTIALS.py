"""
#####################################
##           Gherkin               ##
#####################################

Rule Identifier:
    IAM_USER_NO_SERVICE_SPECIFIC_CREDENTIALS

Rule Name:
    iam-user-no-service-specific-credentials

Description:
  Checks that there are no Service Specific Credentials associated with any IAM Users

Rationale:
   consider short-term API keys with their built-in expiration mechanism. Long-term API keys should only be implemented when neither STS credentials nor short-term credentials are viable options.

Indicative Severity:
  Medium

Trigger:
  Periodic

Reports on:
  AWS::IAM::User

Rule Parameters:
  None

Scenarios:
  Scenario: 1
    Given: There are no IAM Users in the account
        Then: Return empty

  Scenario: 2
    Given: There are no ServerSpecificCredentials attached to the IAM User
        Then: Return COMPLIANT

  Scenario: 3
    Given: There are ServerSpecificCredentials attached to the IAM User
        And: 'ServiceName' parameter was not specified
        And: The ServerSpecificCredentials are not 'Active'
        Then: Return COMPLIANT

  Scenario: 4
    Given: There are ServerSpecificCredentials attached to the IAM User
        And: 'ServiceName' parameter was specified
        And: 'ServiceName' parameter matches ServerSpecificCredentials['ServiceName']
        And: The ServerSpecificCredentials are not 'Active'
        Then: Return COMPLIANT

  Scenario: 5
    Given: There are ServerSpecificCredentials attached to the IAM User
        And: 'ServiceName' parameter was specified
        And: 'ServiceName' parameter does not match ServerSpecificCredentials['ServiceName']
        Then: Return COMPLIANT

  Scenario: 6
    Given: There are ServerSpecificCredentials attached to the IAM User
        And: 'ServiceName' parameter was not specified
        And: The ServerSpecificCredentials are 'Active'
        Then: Return NON_COMPLIANT

  Scenario: 7
    Given: There are ServerSpecificCredentials attached to the IAM User
        And: 'ServiceName' parameter was specified
        And: 'ServiceName' parameter matches ServerSpecificCredentials['ServiceName']
        And: The ServerSpecificCredentials are 'Active'
        Then: Return NON_COMPLIANT

  Scenario: 8
    Given: An error was encountered listing ServerSpecificCredentials for the IAM User
        Then: log the error
        Then: Return NON_COMPLIANT

  Scenario: 9
    Given: An error was encountered listing IAM Users
        Then: log the error
        Then: Raise Exception
"""
from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

RESOURCE_TYPE = "AWS::IAM::User"

class IAM_USER_NO_SERVICE_SPECIFIC_CREDENTIALS(ConfigRule):

    def get_credentials_for_user(self, iam_client, user_name, service_name):
        if service_name == None:
            return iam_client.list_service_specific_credentials(UserName=user_name)
        return iam_client.list_service_specific_credentials(
            UserName=user_name,
            ServiceName=service_name
        )
        

    def evaluate_user(self, user_id, credentials):
        for cred in credentials['ServiceSpecificCredentials']:
            if (cred['Status'] == 'Active'):
                return Evaluation(
                    ComplianceType.NON_COMPLIANT,
                    resourceId=user_id,
                    resourceType=RESOURCE_TYPE,
                    annotation=f'Active service specific credential found: {cred["ServiceSpecificCredentialId"]}'
                )
        return Evaluation(
            ComplianceType.COMPLIANT, 
            resourceId=user_id,
            resourceType=RESOURCE_TYPE,
            annotation='No active ServiceSpecific credentials found'
        )


    def handle_credential_check_error(self, e, user_id):
        msg = 'Encountered error checking credentials'
        print(f'[ERROR] {msg}: {str(e)}')
        # intentional over-reporting with annotation to ensure all IAM Users are evaluated
        return Evaluation(
            ComplianceType.NON_COMPLIANT,
            resourceId=user_id,
            resourceType=RESOURCE_TYPE,
            annotation=f'{msg}. Check custom rule lambda logs'
        )


    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []
        service_name = valid_rule_parameters['ServiceName'] if 'ServiceName' in valid_rule_parameters else None
        iam_client = client_factory.build_client('iam')

        try:
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    user_id = user['UserId']
                    user_name = user['UserName']
                    try:
                        credentials = self.get_credentials_for_user(iam_client, user_name, service_name)
                        evaluations.append(self.evaluate_user(user_id, credentials))
                    except Exception as e:
                        evaluations.append(self.handle_credential_check_error(e, user_id))
            return evaluations
        except Exception as e:
            print(f'[ERROR] Failure listing IAM users: {str(e)}')
            raise e


def lambda_handler(event, context):
    my_rule = IAM_USER_NO_SERVICE_SPECIFIC_CREDENTIALS()
    evaluator = Evaluator(my_rule, [RESOURCE_TYPE])
    return evaluator.handle(event, context)
