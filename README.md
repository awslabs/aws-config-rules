# AWS Config Rules Repository

AWS Community repository of custom Config rules. [Here's the list](https://github.com/awslabs/aws-config-rules/blob/master/RULES.md). Contributions welcome. Instructions for leveraging these rules are below.

## Adding a rule to AWS Config
You can use the sample functions in this repository to create Config rules that evaluate the configuration settings of your AWS resources. First, you use AWS Lambda to create a function that is based on the sample code. Then, you use AWS Config to create a rule that is associated with the function. When the rule’s trigger occurs, AWS Config invokes your function to evaluate your AWS resources.

Add a rule to AWS Config by completing the following steps. For more detailed steps, see [Developing a Custom Rule for AWS Config](http://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_nodejs.html) in the *AWS Config Developer Guide*.

1.	Sign in to the AWS Management Console and open the AWS Lambda console at https://console.aws.amazon.com/lambda/. Verify that your region is set to one that supports AWS Config rules (currently US East, N. Virginia).
3.	Use the AWS Lambda console to create a Lambda function.  
    For the Lambda function code, copy and paste the code from the sample that you want to use.  
    For the role that you assign to your function, choose the **AWS Config role** option to create a role that grants AWS Config permission to invoke the function.  
4.	After you create the function, take note of its ARN.
5.	Open the AWS Config console at https://console.aws.amazon.com/config/.
6.	Use the AWS Config console to add a custom rule.  
    For **AWS Lambda function ARN**, specify the ARN of the function that you created.  
    For **Trigger type**, if you are using any of the *triggered samples* from this repository (file name ends with ```triggered```), choose **Configuration changes**. If you are using any of the *periodic* samples from this repository (file name ends with ```periodic```), choose **Periodic**.
    For the rule parameters, specify any required parameters that are documented in the [list of AWS Config rules (RULES.md)](./RULES.md). 

After you create the rule, it displays on the **Rules** page, and AWS Config invokes its Lambda function. A summary of the evaluation results appears after several minutes.
