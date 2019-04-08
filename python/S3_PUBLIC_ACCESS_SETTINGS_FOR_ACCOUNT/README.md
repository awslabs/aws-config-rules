# Warning!!! This rule requires an additional step to use.
Prior to rule deployment additional libraries must be added to make this rule function as it requires versions of BOTO3 and BOTOCORE greater than what can be currently supported by AWS lambda.

1. Change directory to the parent folder of S3_PUBLIC_ACCESS_SETTINGS_FOR_ACCOUNT
2. Create newboto directory

     ```   mkdir S3_PUBLIC_ACCESS_SETTINGS_FOR_ACCOUNT/newboto ```
3. Add current libraries to S3_PUBLIC_ACCESS_SETTINGS_FOR_ACCOUNT/newboto folder

```pip3 install boto3 botocore urllib3 --system --no-deps --target='S3_PUBLIC_ACCESS_SETTINGS_FOR_ACCOUNT/newboto/'```

4. Deploy as normal

     ```    rdk deploy S3_PUBLIC_ACCESS_SETTINGS_FOR_ACCOUNT ```
