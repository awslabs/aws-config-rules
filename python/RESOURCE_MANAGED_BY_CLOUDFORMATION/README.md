# CloudFormation Management Rule

An AWS Config rule to check whether a resource is managed by CloudFormation. Those that are are `COMPLIANT`, and those that are not are `NON_COMPLIANT`.

## Parameters

None

## Trigger

Periodic

## Supported Reource Types

* `AWS::IAM::ManagedPolicy`
* `AWS::IAM::Role`
  * Special exception granted to service-linked roles
