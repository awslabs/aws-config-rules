# Contributing

Thank you for contributing to the RESOURCE_MANAGED_BY_CLOUDFORMATION AWS Config rule! This document is meant to be a technical guide on how to contribute, not a code of conduct. Please refer to the repository owner for community guidelines and contribution expectations.

## Adding support for new resources

1. Define a function as `build_namespace_resource_type_list` e.g.:

  ```py
  def build_iam_role_list():
  ```

  The function should return a `list[]` of `dict`s. If any resources are except from this list (i.e. cannot technically be managed by CloudFormation, not counting coverage gaps), these may be exempted from the list at this time. Examples are service-linked roles which are created and managed by AWS.
2. Identify the form of the `PhysicalResourceId` reported by CloudFormation and the `ComplianceResourceId` expected by Config. These are not always the same value; one might be the resource name and the other might be the ARN. If you are using the [rdk](https://github.com/awslabs/aws-config-rdk#edit-rules-locally), run `rdk sample-ci <Resource Type>` to determine the `ComplianceResourceId`. For the `PhyiscalResourceId` it might be easiest to check an existing CloudFormation stack manageing that type of resource to determine the format for that resource type.
3. Add logic to the `evaluate_compliance` function in the form `compliance_result.extend(check_resource_managaed_by_cloudformation('AWS::Resource::Type', resourceList, nameProperty, idProperty))`. The `nameProperty` and `idProperty` values should be the corresponding properties from the `dict` of the resource whose values match the `PhysicalResourceId` and `ComplianceResourceId` respectively.
4. Deploy your code, check the results, and open a PR!
