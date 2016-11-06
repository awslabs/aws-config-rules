# AWS Config Rules

### 1. Ensure an IAM password policy exists. 
Description: Checks to see if there is a password policy section enabled in IAM.

	old-periodic/iam_password_policy_enabled-periodic.js

Trigger Type: ```Periodic```
Required Paramters: ```None```

### 2. Ensure IAM password policy requires a minimum number of characters.
Description: Checks that the IAM password policy requires minimum number of characters

	old-periodic/iam_password_minimum_length-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```MinimumPasswordLength```
Example Value: ```12```

### 3. Ensure IAM password policy sets maximum password age.
Description: Checks that the IAM password policy enforces a maximum password age

	old-periodic/iam_password_maximum_age-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```MaxPasswordAge```
Example Value: ```90```

### 4. Ensure IAM password policy requires an uppercase character.
Description: Checks that the IAM password policy requires an uppercase character

	old-periodic/iam_password_require_uppercase-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 5. Ensure IAM password policy requires a lowercase character.
Description: Checks that the IAM password policy requires a lowercase character

	old-periodic/iam_password_require_lowercase-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 6. Ensure IAM password policy requires a number.
Description: Checks that the IAM password policy requires a number

	old-periodic/iam_password_require_number-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 7. Ensure IAM password policy requires a symbol.
Description: Checks that the IAM password policy requires a symbol

	old-periodic/iam_password_require_symbol-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 8. Ensure IAM password policy prevents password reuse.
Description: Checks that the IAM password policy prevents password reuse

	old-periodic/iam_password_require_reuse-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```PasswordReusePrevention```
Example Value: ```24```

### 9. Ensure EC2 Instances have desired tenancy
Description: Checks that EC2 Instances have desired tenancy

	node/instance_desired_tenancy-triggered.js

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:Instance```
Required Parameter: ```DesiredTenancy```
Example Value: ```dedicated```

### 10. Ensure CloudTrail is enabled in all regions.
Description: Checks that CloudTrail is enabled in all regions. Use this rule only in your home region 

	old-periodic/cloudtrail_enabled_all_regions-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 11. Ensure IAM User Access Key Rotation
Description: Checks that the IAM User's Access Keys have been rotated within the specified number of days.

	node/iam_access_key_rotation-triggered.js

Trigger Type: ```Change Triggered```
Scope of Changes: ```IAM:User```
Required Parameter: ```MaximumAPIKeyAge```
Example Value: ```90```

### 12. Ensure Access Key Disabled on Root Account
Description: Checks that the Root Account's Access Keys have been disabled.

	old-periodic/iam_access_key_root_disabled-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 13. Ensure MFA Enabled on Root Account
Description: Checks that the Root Account has MFA Enabled

	old-periodic/iam_mfa_require_root-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 14. Ensure IAM User has MFA Enabled
Description: Checks that all IAM Users have MFA Enabled

	node/iam_mfa_require-triggered.js

Trigger Type: ```Change Triggered```
Scope of Changes: ```IAM:User```
Required Parameter: ```None```

### 15. Ensure CloudTrail Log Validation is Enabled in All Regions
Description: Checks that CloudTrail Log Validation is Enabled in All Regions

	old-periodic/cloudtrail_validation_all_regions-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 16. Ensure AWS Config is Enabled in All Regions
Description: Checks that AWS Config is Enabled in All Regions

	old-periodic/config_enabled_in_region-periodic.js

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 17. Ensure all EC2 Instances are of a Given Type
Description: Checks that all EC2 instances are of the type specified

	python/ec2_desired_instance_type-triggered.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:Instance```
Required Parameter: ```desiredInstanceType```
Example Value: ```t2.small```

See https://aws.amazon.com/ec2/instance-types/ for more instance types

### 18. Ensure fewer resources than provided count for  a Given Type
Description: Checks that the number of resources that are active is lower than specified count for a given resource type.

	old-periodic/resource_type_max_count-periodic.py

Trigger Type: ```Periodic```
Required Parameters: ```applicableResourceType```, ```maxCount```
Example Value: ```AWS::EC2::Instance```, ```10```

See http://docs.aws.amazon.com/config/latest/APIReference/API_ListDiscoveredResources.html
for resource types.

### 19. Ensure VPC Flow Logs is enabled.
Description: Checks that VPC Flow Logs is enabled at specific VPC

	python/vpc_flow_logs_enabled.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:VPC```
Required Resource Identifier: ```VPC ID```
Example Value: ```vpc-xxxxxxxx```

### 20. Ensure that no security groups allow public access to the specified ports.
Description: Checks that all security groups block access to the specified ports.

	python/ec2-exposed-group.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:SecurityGroup```
Accepted Parameters: ```examplePort1```, ```exampleRange1```, ```examplePort2```, ...
Example Values: ```8080```, ```1-1024```, ```2375```, ...

### 21. Ensure that no EC2 instances allow public access to the specified ports.
Description: Checks that all instances block access to the specified ports.

	python/ec2-exposed-instance.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:Instance```
Accepted Parameters: ```examplePort1```, ```exampleRange1```, ```examplePort2```, ...
Example Values: ```8080```, ```1-1024```, ```2375```, ...

### 22. Ensure that no users have been inactive for a period longer than specified.
Description: Checks that all users have been active for earlier than specified.

	python/ec2-inactive-user.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```IAM:User```
Required Parameters: ```maxInactiveDays```
Example Value: ```90```

### 23. Ensure that no users have password policy requirements weaker than specified.
Description: Checks that all users have strong password policy requirements.

	python/iam-password-policy.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:User```
Accepted Parameters: ```requireNumbers```, ```expirePassword```, ```hardExpiry```, ```minimumPasswordLength```, ```requireSymbols```, ```requireUppercaseCharacters```, ```requireLowercaseCharacters```, ```allowUsersToChangePassword```, ```passwordReusePrevention```
Example Values: ```true```, ```true```, ```false```, ```6```, ```true```, ```true```, ```true```, ```true```, ```5```

### 24. Ensure that no users have access keys that have never been used.
Description: Checks that all users have only active access keys.

	python/iam-unused-keys.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```IAM:User```

### 25. Ensure that there are no users that have never been logged in.
Description: Checks that all users have logged in at least once.

	python/iam-unused-user.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```IAM:User```

### 26. Ensure that no users have multiple factor authentication disabled.
Description: Checks that all users have enabled multiple factor authentication.

	python/iam-mfa.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```IAM:User```

### 27. Ensure all EC2 Instances that have a certain tag format also have a specific security group
Description: Checks that all EC2 instances that have match a tag format (via regex) also have a specific security group. For example, a tag regex of ```^prod(us|eu|br)[lw]box[0-9]{3}$``` will match ```produslbox001```.

	python/ec2_require_security_group_by_tag.py

Trigger Type: ```Change Triggered```
Scope of Changes: ```EC2:Instance```
Required Parameters: ```namePattern```, ```securityGroupName```
Example Value: ```^prod(us|eu|br)[lw]box[0-9]{3}$```, ```MyTestGroup```

### 28. Ensure MFA Enabled on Root Account
Description: Checks that the Root Account has MFA Enabled

	java/src/main/java/com/amazonaws/services/config/samplerules/RootAccountMFAEnabled.java

Trigger Type: ```Periodic```
Required Parameter: ```None```

### 29. Required tags with multiple valid values
Description: Checks that the required tags exist and has a value matching one in the comma-separated list

	python/ec2_require_tags_with_valid_values.py

Trigger Type: ```Change Triggered```
Required Parameter: ```requiredTagKey1```, ```requiredTagValues1```, ```requiredTagKey2```, ...

### 30. Verify that RDS DB Instances are encrypted
Description: Checks that the RDS DB instance is encrypted. If an optional KMS key ARN is provided, then whether encryption was done with provided key

	node/rds_db_instance_encrypted.js

Trigger Type: ```Change Triggered```
Required Parameter: ```None```

### 31. Verify that EC2 Security Group Ingress rules are correct
Description: Checks that that the ingress permissions on an EC2 Security Group are correct and adjusts them if they are incorrect.

	python/ec2_security_group_ingress.py

Trigger Type: ```Change Triggered```
Required Parameter: ```None```

### 32. Check that no EC2 Instances are publicly accessible except 80 and 443.
Description: Check that no security groups allow public access to the ports other then 80 and 443.

	python/ec2_sg_public_ingress_excluding_80_443.py

Trigger Type: ```Change Triggered```
Required Parameter: ```None```

### 33. Check that no EC2 Instances are in Public Subnet.
Description: Check that no EC2 Instances are in Public Subnet.

	python/ec2_vpc_public_subnet.py

Trigger Type: ```Change Triggered```
Required Parameter: ```None```

### 34. Check that no RDS Instances are in Public Subnet.
Description: Check that no RDS Instances are in Public Subnet.

	python/rds_vpc_public_subnet.py

Trigger Type: ```Change Triggered```
Required Parameter: ```None```
