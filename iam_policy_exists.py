#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure one or several specific IAM policies exist
# Description: Checks that defined IAM policies have been defined in AWS IAM.
#
# Trigger Type: Periodic
# Scope of Changes: N/A
# Required Parameter name: PoliciesToCheck
# Required Parameter value example: policy-name1,policy-name2 (split multiple rule name with a ",")

import boto3
import json


def evaluate_compliance(rule_parameters, account_id):
	fails = 0
	client = boto3.client("iam")
	
	if 'PoliciesToCheck' in rule_parameters:
		for policy in rule_parameters["PoliciesToCheck"].split(","):
			policyARN = "arn:aws:iam::%s:policy/%s" %(account_id, policy)
			print(policyARN)
			try:
				response = client.get_policy(PolicyArn=policyARN)
			except:
				fails = fails + 1
	else:
		print("No IAM policy defined in parameter")
		fails = fails + 1
	if fails == 0:
		return "COMPLIANT"
	else:
		return "NON_COMPLIANT"


def lambda_handler(event, context):
    account_id = event['accountId']
    invoking_event = json.loads(event["invokingEvent"])
    print(invoking_event)
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
                'ComplianceType': evaluate_compliance(rule_parameters, account_id),
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            },
        ],
        ResultToken=event['resultToken']
    )