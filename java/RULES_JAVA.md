# AWS Config Rules (Java)
This file provides supplementary information for the sample AWS Config Rules in Java.

* **Handler** - The handler value that you provide to AWS Lambda when you create a function.
* **Supplementary Permissions** - Permissions that you must grant the function's execution role in addition to those that are granted by the AWS Config role.
* **Trigger Type** - The trigger type that you assign to the Config rule that uses the function.
* **Required Parameters** - Parameters that are evaluated by the function. You must specify these parameter keys when you create the AWS Config rule.

For the steps to create a Config rule with a Java sample, see the [HOWTO.md](./HOWTO.md) file.

## 1. Ensure MFA Enabled on Root Account
Description: Checks whether an AWS account is enabled for multi-factor authentication.

    \src\main\java\com\amazonaws\services\config\samplerules\RootAccountMFAEnabled.java

* Handler: ```com.amazonaws.services.config.samplerules.RootAccountMFAEnabled::handle```
* Supplementary Permissions: ```iam:GetAccountSummary```
* Trigger Type: ```Periodic```
* Required Parameters: ```None```
