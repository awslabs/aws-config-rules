#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Created with the Rule Development Kit: https://github.com/awslabs/aws-config-rdk
# Can be used stand-alone or with the Rule Compliance Engine: https://github.com/awslabs/aws-config-engine-for-compliance-as-code
#

'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK

Description:
  Check whether the Amazon EBS snapshots are not publicly restorable. The rule is NON_COMPLIANT if the RestorableByUserIds field is set to 'all'. 

Trigger:
  Periodic

Reports on:
  AWS::::Account

Rule Parameters:
  None

Scenarios:
  Scenario: 1
    Given: No snapshots with RestorableByUserIds parameter set to 'all'
     Then: Return NOT_APPLICABLE
  Scenario: 2
    Given: One or more snapshots with RestorableByUserIds parameter set to 'all'
     Then: Return NON_COMPLIANT with Annotation containing SnapshotIDs
'''

