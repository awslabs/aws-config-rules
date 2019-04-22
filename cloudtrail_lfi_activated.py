#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure CloudTrail log file validation is enabled
# Description: Checks that tracked trails have log file integrity activated.
#
# Trigger Type: Change Triggered
# Scope of Changes: AWS::CloudTrail::Trail
# Required Parameters: None

import json
import boto3

APPLICABLE_RESOURCES = ["AWS::CloudTrail::Trail"]

def evaluate_compliance(configuration_item):
	if (configuration_item["resourceType"] not in APPLICABLE_RESOURCES) or (configuration_item["configurationItemStatus"] == "ResourceDeleted"):
		return {
			"compliance_type": "NOT_APPLICABLE",
			"annotation": "NOT_APPLICABLE"
		}

	lfi_status = configuration_item["configuration"]["logFileValidationEnabled"]

	if lfi_status:
		return {
			"compliance_type": "COMPLIANT",
			"annotation": 'Log File Validation is enabled.'
		}
	else:
		return {
			"compliance_type": "NON_COMPLIANT",
			"annotation": 'Log File Validation is disabled.'
		}
	
def lambda_handler(event, context):
	invoking_event      = json.loads(event['invokingEvent'])
	configuration_item  = invoking_event["configurationItem"]
	evaluation          = evaluate_compliance(configuration_item)
	config              = boto3.client('config')
	
	result_token = "No token found."
	if "resultToken" in event:
		result_token = event["resultToken"]
	
	config.put_evaluations(
		Evaluations=[
			{
				"ComplianceResourceType":	configuration_item["resourceType"],
				"ComplianceResourceId":		configuration_item["resourceId"],
				"ComplianceType":			evaluation["compliance_type"],
				"Annotation":				evaluation["annotation"],
				"OrderingTimestamp":		configuration_item["configurationItemCaptureTime"]
			},
		],
		ResultToken=result_token
	)