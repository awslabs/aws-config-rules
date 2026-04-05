# AWS Config Custom Rules: API Gateway Requiring Authorizer

AWS API Gateway allows for the configuration of an Authorizer, which provides support to Authorize user access based upon some supplied identity. Many API Gateways do not require Authorisation, or use API Gateway Resource Policies to manage an IP Whitelist, or leverage AWS WAF.

This custom AWS Config rule implements a check that all API Gateway Stages must have Authorizers correctly configured. You can add parameters that create validation that not only is an Authorizer required, but that it must be a specific Authorizer. Stages that have no resource methods are not considered in violation, but any resource methods that contain no authorisation will result in the entire API Gateway Stage as being marked as non-compliant.

## Pre-requisites

We recommend installation and configuration through [RDK](https://github.com/awslabs/aws-config-rdk). Please follow the instructions on Github to install RDK into your environment.

## Installation

This custom rule has been built through RDK. To install, please run `rdk deploy API_GW_REQUIRE_AUTHORIZER` from the parent directory.

## Configuration

The sample `parameters.json` file demonstrates how to setup that not only is an Authorizer required on all API Gateway Stages, but that it must use AWS IAM:

```
{
  "Version": "1.0",
  "Parameters": {
    "RuleName": "API_GW_REQUIRE_AUTHORIZER",
    "SourceRuntime": "python3.7",
    "CodeKey": "API_GW_REQUIRE_AUTHORIZER.zip",
    "InputParameters": "{\"RequireAuthTypes\":[\"AWS_IAM\"]}",
    "OptionalParameters": "{}",
    "SourceEvents": "AWS::ApiGateway::Stage"
  },
  "Tags": "[]"
}

```

Specifically, `InputParameters` is set to an array of Strings, which represent valid Authoriser Types on each resource method. Valid Values are: `AWS_IAM`, `TOKEN` or `REQUEST` for Lambda Authorisers, or `COGNITO_USER_POOLS` for Cognito. Please note that a single resource method can have multiple Authorizers, but this Config Rule only checks that any of the supplied Required Authorization Types is configured.

## Removal

You can remove this Config Rule through RDK, using `rdk undeploy API_GW_REQUIRE_AUTHORIZER`.

----

AWS Labs 2020