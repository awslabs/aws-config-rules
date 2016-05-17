# Creating an AWS Config Rule with Java

You can use any of the sample Java files in this repository to create a custom Config rule. To
create a Config rule, first you build a JAR file that contains the Java classes. Then, you create an AWS Lambda
function that uses one of the classes in the JAR. Finally, you create a Config rule that uses the function.

To build the JAR file, you will run a single Apache Maven command. Maven will download the package's
dependencies, build the package, and test it. To download and install Maven, go to
<https://maven.apache.org/>.

## Building the JAR File

Run the following Maven command from within the ''java'' directory:

`mvn package`

Maven builds a JAR file and places it in the following path:

'target/aws-config-java-sample-rules-1.0-SNAPSHOT.jar'

## Creating an AWS Lambda Function and AWS Config Rule

For steps to create create a Lambda function and corresponding Config rule, see the [README
file](../README.md) for the AWS Config Rules repository.

When you use AWS Lambda to create the function, select Java 8 as the runtime. You will need to
specify the function handler, and you might need to add supplementary permissions to the function's
execution role. This information is documented in the [list of Java Config rules
(RULES.md)](RULES_JAVA.md).