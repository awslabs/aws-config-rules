#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensure CloudTrail is encrypted
# Description: Checks that tracked trails are encrypted (optionally with a specific KMS Key).
#
# Trigger Type: Change Triggered
# Scope of Changes: AWS::CloudTrail::Trail
# Required Parameters: None
# Optional Parameter: KMSKeyARN 
# Optional Parameter value example : arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab

import json
import boto3

APPLICABLE_RESOURCES = ["AWS::CloudTrail::Trail"]
OPTIONAL_PARAMETER = "KMSKeyARN"

# Verify the optional parameter, set the parameter to "None" if not existant
def normalize_optional_parameter(rule_parameters,optional_parameter):
	if not rule_parameters:
		rule_parameters = {optional_parameter: "None"}
		print(optional_parameter+ " set to 'None'")
	else:
		if not optional_parameter in rule_parameters:
			rule_parameters = {optional_parameter: "None"}
			print(optional_parameter+ " set to 'None'")
		else:
			print(optional_parameter+ " set to rule parameter value: " + rule_parameters[optional_parameter])
	return rule_parameters

# Verify compliance
def evaluate_compliance(configuration_item, rule_parameters, optional_parameter):
	if (configuration_item["resourceType"] not in APPLICABLE_RESOURCES) or (configuration_item["configurationItemStatus"] == "ResourceDeleted"):
		return {
			"compliance_type": "NOT_APPLICABLE",
			"annotation": "NOT_APPLICABLE"
		}
	
	compliance_status = False
	print configuration_item
	kms_key_id = configuration_item["configuration"]["kmsKeyId"]
	print kms_key_id
	if kms_key_id == rule_parameters[optional_parameter] and kms_key_id != "None":
		return {
			"compliance_type": "COMPLIANT",
			"annotation": 'Encryption is enabled with the specified KMS key [' + kms_key_id + '].'
		}
	elif rule_parameters[optional_parameter] == "None" and kms_key_id != "None":
		return {
			"compliance_type": "COMPLIANT",
			"annotation": 'Encryption is enabled (no key specified in the Rule).'
		}
	elif kms_key_id != rule_parameters[optional_parameter] and kms_key_id != "None":
		return {
			"compliance_type": "NON_COMPLIANT",
			"annotation": 'Encryption is enabled with [' + kms_key_id +  ']. It is not with the specified KMS key in the rule [' + rule_parameters[optional_parameter] + '].'
		}
	else:
		return {
			"compliance_type": "NON_COMPLIANT",
			"annotation": 'Encryption is disabled.'
		}

# Start of the lambda function
def lambda_handler(event, context):
	invoking_event      = json.loads(event['invokingEvent'])
	configuration_item  = invoking_event["configurationItem"]
	
	rule_parameters 	= json.loads(event["ruleParameters"])
	print rule_parameters
	
	rule_parameters = normalize_optional_parameter(rule_parameters,OPTIONAL_PARAMETER)
	print rule_parameters
	
	evaluation          = evaluate_compliance(configuration_item, rule_parameters)
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