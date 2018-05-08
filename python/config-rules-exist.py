#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure one or several specific Config Rules exist
# Description: Checks that specific config rules exists, including itself if configured.
#
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameter name: ConfigRules
# Required Parameter value example: config-rule-name1,config-rule-name2 (split multiple rule name with a ",")


import boto3
import json


def evaluate_compliance(rule_parameters):
    if 'ConfigRules' in rule_parameters:
        rulesToCheck = []
        for rules in rule_parameters["ConfigRules"].split(","):
            rulesToCheck.append(rules)
    else:
        print("No Rules defined in parameter")
    #print rulesToCheck
    fails = 0

    client = boto3.client('config')
    try:
        response = client.describe_config_rules(ConfigRuleNames=rulesToCheck)
        for i in response["ConfigRules"]:
            ruleActive = i["ConfigRuleState"]
            print(i)
            if ruleActive == "ACTIVE":
                pass
            else:
                fails = fails + 1

    except:
        fails = fails + 1

    if fails == 0:
        return "COMPLIANT"
    else:
        return "NON_COMPLIANT"



def lambda_handler(event, context):
    account_id = event['accountId']
    invoking_event = json.loads(event["invokingEvent"])
    print (invoking_event)
    rule_parameters = json.loads(event["ruleParameters"])
    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': 'AWS::::Account',
                'ComplianceResourceId': account_id,
                'ComplianceType': evaluate_compliance(rule_parameters),
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            },
        ],
        ResultToken=event['resultToken']
    )
