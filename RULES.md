# AWS Config Rules

### 1. Ensure an IAM password policy exists. 
Description: Checks to see if there is a password policy section enabled in IAM.

	node/iam_password_policy_enabled-periodic.js

Required Paramters:```None```

### 2. Ensure IAM password policy requires a minimum number of characters.
Description: Checks that the IAM password policy requires minimum number of characters

	node/iam_password_minimum_length-periodic.js
    
Required Parameter: ```MinimumPasswordLength```
Example Value: ```12```

### 3. Ensure IAM password policy sets maximum password age.
Description: Checks that the IAM password policy enforces a maximum password age

	node/iam_password_maximum_age-periodic.js
    
Required Parameter: ```MaxPasswordLength```
Example Value: ```90```

### 4. Ensure IAM password policy requires an uppercase character.
Description: Checks that the IAM password policy requires an uppercase character

	node/iam_password_require_uppercase-periodic.js
    
Required Parameter: ```None```

### 5. Ensure IAM password policy requires a lowercase character.
Description: Checks that the IAM password policy requires a lowercase character

	node/iam_password_require_lowercase-periodic.js
    
Required Parameter: ```None```

### 6. Ensure IAM password policy requires a number.
Description: Checks that the IAM password policy requires a number

	node/iam_password_require_number-periodic.js
    
Required Parameter: ```None```

### 7. Ensure IAM password policy requires a symbol.
Description: Checks that the IAM password policy requires a symbol

	node/iam_password_require_symbol-periodic.js
    
Required Parameter: ```None```

### 8. Ensure IAM password policy prevents password reuse.
Description: Checks that the IAM password policy prevents password reuse

	node/iam_password_require_reuse-periodic.js
    
Required Parameter: ```PasswordReusePrevention```
Example Value: ```24```

### 9. Ensure EC2 Instances have desired tenancy
Description: Checks that EC2 Instances have desired tenancy

	node/instance_desired_tenancy-triggered.js
    
Required Parameter: ```DesiredTenancy```
Example Value: ```dedicated```

### 10. Ensure CloudTrail is enabled in all regions.
Description: Checks that CloudTrail is enabled in all regions. Use this rule only in your home region 

	node/cloudtrail_enabled_all_regions-periodic.js
    
Required Parameter: ```None```

### 11. Ensure IAM User Access Key Rotation
Description: Checks that the IAM User's Access Keys have been rotated within the specified number of days.

	node/iam_access_key_rotation-triggered.js
    
Required Parameter: ```MaximumAPIKeyAge```
Example Value: ```90```

### 12. Ensure Access Key Disabled on Root Account
Description: Checks that the Root Account's Access Keys have been disabled.

	node/iam_access_key_root_disabled-periodic.js
    
Required Parameter: ```None```

### 13. Ensure MFA Enabled on Root Account
Description: Checks that the Root Account has MFA Enabled

	node/iam_mfa_require_root-periodic.js
    
Required Parameter: ```None```

### 14. Ensure IAM User has MFA Enabled
Description: Checks that all IAM Users have MFA Enabled

	node/iam_mfa_require-triggered.js
    
Required Parameter: ```None```

### 15. Ensure CloudTrail Log Validation is Enabled in All Regions
Description: Checks that CloudTrail Log Validation is Enabled in All Regions

	node/cloudtrail_validation_all_regions-periodic.js
    
Required Parameter: ```None```

### 16. Ensure AWS Config is Enabled in All Regions
Description: Checks that AWS Config is Enabled in All Regions

	node/config_enabled_in_region-periodic.js
    
Required Parameter: ```None```

### 17. Ensure all EC2 Instances are of a Given Type
Description: Checks that all EC2 instances are of the type specified

	python/ec2_desired_instance_type-triggered.py
    
Required Parameter: ```desiredInstanceType```
Example Value: ```t2.small```

See https://aws.amazon.com/ec2/instance-types/ for more instance types

### 18. Ensure all EC2 Instances are of a Given Type
Description: Checks that all EC2 instances are of the type specified

	python/resource_type_max_count-periodic.py
    
Required Parameters: ```applicableResourceType```, ```maxCount```
Example Value: ```AWS::EC2::Instance```, ```10```

See http://docs.aws.amazon.com/config/latest/APIReference/API_ListDiscoveredResources.html
for resource types.

### 19. Ensure VPC Flow Logs is enabled.
Description: Checks that VPC Flow Logs is enabled at specific VPC

	python/vpc_flow_logs_enabled.py

Required Resource Identifier: ```VPC ID```
Example Value: ```vpc-xxxxxxxx```
