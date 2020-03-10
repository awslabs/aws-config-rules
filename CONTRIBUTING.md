# Contributing to AWS Config Rules Repository
Welcome to the contributing section. Thanks a lot for considering going through the process, we will make is as enjoyable as possible!

## Our Mission
Build high-quality rules that can be reused or inspire the community.

## Building your first Rule
We are recommending to use the [Rule Development Kit](https://github.com/awslabs/aws-config-rdk). The RDK increases your rule coding speed by an order of magnitude and you can get started relatively fast. We suggest to use Python due to the maturity of the tooling and the community. 

Here's a blog post to get started with the RDK: https://aws.amazon.com/blogs/mt/how-to-develop-custom-aws-config-rules-using-the-rule-development-kit/

## Publishing your Rule
1. (python) Pylint your rule using pylint and the rcfile python/pylintrc
2. Do a Pull Request from your fork.
3. (python) Good-bot will verify that your score is 10/10 with no findings.
4. Our team will review it manually and merge your PR.
5. Et voila!
