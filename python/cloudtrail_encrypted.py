"""
    This file made available under CC0 1.0 Universal
    (https://creativecommons.org/publicdomain/zero/1.0/legalcode)

    Ensure CloudTrail is encrypted
    Description: Checks that tracked trails are encrypted (optionally with a specific KMS Key).

    Trigger Type: Change Triggered
    Scope of Changes: AWS::CloudTrail::Trail
    Required Parameters: None
    Optional Parameter: KMSKeyARN
    Optional Parameter value example :
        arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
"""

import logging
import json
import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

AWS_CONFIG = boto3.client('config')

APPLICABLE_RESOURCES = ["AWS::CloudTrail::Trail"]
OPTIONAL_PARAMETER = "KmsKeyArn"


def normalize_optional_parameter(rule_parameters):
    """
        Verify the optional parameter, set the parameter to "None" if not existant
    """
    if not rule_parameters:
        rule_parameters = {OPTIONAL_PARAMETER: None}
        LOG.debug("%s set to None", OPTIONAL_PARAMETER)
    else:
        if OPTIONAL_PARAMETER not in rule_parameters:
            rule_parameters = {OPTIONAL_PARAMETER: None}
            LOG.debug("%s set to None", OPTIONAL_PARAMETER)
        else:
            LOG.debug(
                "%s set to rule parameter value: %s",
                OPTIONAL_PARAMETER,
                rule_parameters[OPTIONAL_PARAMETER])
    return rule_parameters


def evaluate_compliance(configuration_item, rule_parameters):
    """ Verify compliance"""
    if (configuration_item['resourceType'] not in APPLICABLE_RESOURCES) or \
            (configuration_item['configurationItemStatus'] == 'ResourceDeleted'):
        return {
            'compliance_type': 'NOT_APPLICABLE',
            'annotation': 'NOT_APPLICABLE'
        }

    kms_key_id = configuration_item['configuration'].get('kmsKeyId')
    if kms_key_id is not None:
        if kms_key_id == rule_parameters[OPTIONAL_PARAMETER]:
            return {
                'compliance_type': 'COMPLIANT',
                'annotation':
                    str.format(
                        'Encryption is enabled with the specified KMS key [{0}].',
                        kms_key_id
                    )
            }
        elif rule_parameters[OPTIONAL_PARAMETER] is None:
            return {
                'compliance_type': 'COMPLIANT',
                'annotation': 'Encryption is enabled (no key specified in the Rule).'
            }
        elif kms_key_id != rule_parameters[OPTIONAL_PARAMETER]:
            return {
                'compliance_type': 'NON_COMPLIANT',
                'annotation':
                    str.format(
                        'Encryption is enabled with [{0}]. It is not with the '
                        'specified KMS key in the rule [{1}].', kms_key_id,
                        rule_parameters[OPTIONAL_PARAMETER])
            }

    return {
        'compliance_type': 'NON_COMPLIANT',
        'annotation': 'Encryption is disabled.'
    }


def lambda_handler(event, _):
    """ Lambda handler """
    invoking_event = json.loads(event['invokingEvent'])
    configuration_item = invoking_event['configurationItem']
    rule_parameters = json.loads(event['ruleParameters'])

    rule_parameters = normalize_optional_parameter(rule_parameters)

    evaluation = evaluate_compliance(configuration_item, rule_parameters)

    result_token = "No token found."
    if 'resultToken' in event:
        result_token = event['resultToken']

    AWS_CONFIG.put_evaluations(
        Evaluations=[
            {
                'ComplianceResourceType': configuration_item['resourceType'],
                'ComplianceResourceId': configuration_item['resourceId'],
                'ComplianceType': evaluation['compliance_type'],
                'Annotation': evaluation['annotation'],
                'OrderingTimestamp': configuration_item['configurationItemCaptureTime']
            },
        ],
        ResultToken=result_token
    )
