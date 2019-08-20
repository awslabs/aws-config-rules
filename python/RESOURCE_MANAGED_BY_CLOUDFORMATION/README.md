# CloudFormation Management Rule

An AWS Config rule to check whether a resource is managed by CloudFormation. Those that are are `COMPLIANT`, and those that are not are `NON_COMPLIANT`. This is performed by compiling a list of all the physical resource Ids reported by all CloudFormation stacks in the same region as the rule and comparing to results from listing those resources via their respecitve APIs. This approach goes beyond checking for `aws:cloudformation:` tags as it will capture resources which don't support tags or where CloudFormation does not support tagging those resources yet.

## Parameters

None

## Trigger

Periodic

## Supported Reource Types

* `AWS::IAM::ManagedPolicy`
* `AWS::IAM::Role`
  * Special exception granted to service-linked roles
