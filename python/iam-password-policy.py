#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure that no users have password policy requirements weaker than specified.
# Description: Checks that all users have strong password policy requirements.
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:User
# Accepted Parameters: requireNumbers, expirePassword, hardExpiry, minimumPasswordLength, requireSymbols, requireUppercaseCharacters, requireLowercaseCharacters, allowUsersToChangePassword, passwordReusePrevention
# Example Values: true, true, false, 6, true, true, true, true, 5


import json
import boto3


APPLICABLE_RESOURCES = ["AWS::IAM::User"]


def normalize_parameters(rule_parameters):
    for key, value in rule_parameters.iteritems():
        if value == u"true":
            rule_parameters[key] = True
        elif value == u"false":
            rule_parameters[key] = False
        elif value.isdigit():
            rule_parameters[key] = int(value)
        else:
            rule_parameters[key] = None
        rule_parameters[key[0].upper() + key[1:]] = rule_parameters.pop(key)
    return rule_parameters


def find_violation(password_policy, baseline_policy):
    for field in baseline_policy:
        if field not in password_policy:
            return field + " is not defined."
        elif password_policy[field] is bool:
            if password_policy[field] is not baseline_policy[field] and \
                    baseline_policy[field] is True:
                return field + " is not enabled."
        elif password_policy[field] is int:
            if password_policy[field] < int(baseline_policy[field]):
                return field + " is too short."

    return None


def evaluate_compliance(configuration_item, rule_parameters):
    if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
        return {
            "compliance_type": "NOT_APPLICABLE",
            "annotation": "The rule doesn't apply to resources of type " +
            configuration_item["resourceType"] + "."
        }

    iam = boto3.client("iam")
    password_policy = iam.get_account_password_policy()["PasswordPolicy"]

    violation = find_violation(password_policy, rule_parameters)
    if violation is None:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": "This resource is compliant with the rule."
        }
    else:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": violation
        }


def lambda_handler(event, context):
    invoking_event = json.loads(event["invokingEvent"])
    configuration_item = invoking_event["configurationItem"]
    rule_parameters = normalize_parameters(json.loads(event["ruleParameters"]))

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType":
                    configuration_item["resourceType"],
                "ComplianceResourceId":
                    configuration_item["resourceId"],
                "ComplianceType":
                    evaluation["compliance_type"],
                "Annotation":
                    evaluation["annotation"],
                "OrderingTimestamp":
                    configuration_item["configurationItemCaptureTime"]
            },
        ],
        ResultToken=result_token
    )
