# AWS Config Rules Repository

AWS Community repository of custom Config rules. [Here's the list](https://github.com/awslabs/aws-config-rules/blob/master/RULES.md). Contributions welcome. Instructions for leveraging these rules are below.

With the latest release for AWS Config Rules (http://amzn.to/2aFZZw2), periodic rules can now be triggered without the need for a configuration snapshot. Please refer to http://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_nodejs-sample.html for an example of a periodic rule triggered via scheduled notification. This is now the recommended way to author a periodic rule.
As such, we have moved all existing periodic rules in this repository that leverage the old configuration snapshot periodic trigger under the old-periodic/ directory.

**Please review each rule carefully and test within your dev/test environment before integrating into production**

## Adding a rule to AWS Config
You can use the sample functions in this repository to create Config rules that evaluate the configuration settings of your AWS resources. First, you use AWS Lambda to create a function that is based on the sample code. Then, you use AWS Config to create a rule that is associated with the function. When the rule’s trigger occurs, AWS Config invokes your function to evaluate your AWS resources.

Add a rule to AWS Config by completing the following steps. For more detailed steps, see [Developing a Custom Rule for AWS Config](http://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_nodejs.html) in the *AWS Config Developer Guide*.

1. Navigate to the AWS Lambda Console.
	- Sign in to the AWS Management Console and open the [AWS Lambda console](https://console.aws.amazon.com/lambda/).
	- Verify that your region is set to one that supports AWS Config rules.
	- For the list of supported regions, see [AWS Config Regions and Endpoints](http://docs.aws.amazon.com/general/latest/gr/rande.html#awsconfig_region).
2. Create a Lambda function.
	- Provide your code using the method required by the code entry type that you choose.  
	- If you are adding a Python or Node.js function, you can copy and paste the code from the sample that you want to use. If you are adding a Java function, you must provide a JAR file that contains the Java classes. For instructions to build the JAR file, see [Creating an AWS Config Rule with Java](./java/HOWTO.md).
	- For the role that you assign to your function, choose the **AWS Config Rules permission** option. This includes *AWSConfigRulesExecutionRole*, an AWS managed policy that allows your Lambda function permission to "put" evaluations.
	- For **Handler**, if you are adding a Python or Node.js function, keep the default value. If you are adding a Java function, specify the handler value for to the Java function that you want to use. For the handler values, see [AWS Config Rules (Java)](./java/RULES_JAVA.md).
3. After you create the function, take note of its ARN.  
4. Open the [AWS Config console](https://console.aws.amazon.com/config/).   
	- Verify that your region is set to the same region in which you created the AWS Lambda function for your custom rule.  
5. Use the AWS Config console to add a custom rule.  
	- For **AWS Lambda function ARN**, specify the ARN of the function that you created.
	- For **Trigger type**, if you are using any of the *triggered samples* from this repository, choose **Configuration changes**. If you are using any of the *periodic* samples from this repository, choose **Periodic**.
	- For the rule parameters, specify any required parameters.
	- For the trigger types and required parameters for each function, see [AWS Config Rules](./RULES.md) (for Python and Node.js functions) or [AWS Config Rules (Java)](./java/RULES_JAVA.md).
	- **Note**: When you create a custom rule with the AWS Config console, the appropriate permissions for invoking the Lambda are automatically created for you. If you create a custom rule with the AWS CLI, you need to give AWS Config permission to invoke your Lambda function, using the `aws lambda add-permission` command.

After you create the rule, it displays on the **Rules** page, and AWS Config invokes its Lambda function. A summary of the evaluation results appears after several minutes.
