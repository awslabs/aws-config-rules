# Copyright 2017-2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.
import sys
import unittest
from botocore.exceptions import ClientError

try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = "AWS::Redshift::Cluster"

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()
REDSHIFT_CLIENT_MOCK = MagicMock()
PAGINATOR_MOCK = MagicMock()


class Boto3Mock:
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == "config":
            return CONFIG_CLIENT_MOCK
        if client_name == "sts":
            return STS_CLIENT_MOCK
        if client_name == "redshift":
            return REDSHIFT_CLIENT_MOCK

        raise Exception("Attempting to create an unknown client")


sys.modules["boto3"] = Boto3Mock()

RULE = __import__("REDSHIFT_AUDIT_ENABLED")


class ComplianceTest(unittest.TestCase):

    # Unit test for no Cluster is present -- GHERKIN Scenario 1
    def test_scenario_1(self):
        clusters_is_empty = [{"Clusters": []}]
        REDSHIFT_CLIENT_MOCK.get_paginator.return_value = PAGINATOR_MOCK
        PAGINATOR_MOCK.paginate.return_value = clusters_is_empty
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [
            build_expected_response(
                "NOT_APPLICABLE",
                "123456789012",
                "AWS::::Account",
                annotation="No clusters found",
            )
        ]
        assert_successful_evaluation(self, response, expected_response)

    # Unit test for if LoggingEnabled to false -- GHERKIN Scenario 2
    def test_scenario_2(self):
        clusters_is_present = [
            {
                "Clusters": [
                    {
                        "ClusterIdentifier": "redshift-cluster-1",
                        "NodeType": "ra3.4xlarge",
                        "ClusterStatus": "available",
                        "ClusterAvailabilityStatus": "Available",
                        "MasterUsername": "awsuser",
                        "DBName": "dev",
                        "Endpoint": {
                            "Address": "redshift-cluster-1.crmh4vec7kyo.us-east-2.redshift.amazonaws.com",
                            "Port": 5439,
                        },
                        "ClusterCreateTime": "datetime.datetime(2022, 1, 7, 7, 35, 2, 232000, tzinfo=tzlocal())",
                        "AutomatedSnapshotRetentionPeriod": 1,
                        "ManualSnapshotRetentionPeriod": -1,
                        "ClusterSecurityGroups": [],
                        "VpcSecurityGroups": [
                            {
                                "VpcSecurityGroupId": "sg-065ea7b9c71408f17",
                                "Status": "active",
                            }
                        ],
                        "ClusterParameterGroups": [
                            {
                                "ParameterGroupName": "myparametergroup",
                                "ParameterApplyStatus": "in-sync",
                                "ClusterParameterStatusList": [
                                    {
                                        "ParameterName": "use_fips_ssl",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "query_group",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "datestyle",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "extra_float_digits",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "search_path",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "statement_timeout",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "wlm_json_configuration",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "require_ssl",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "enable_user_activity_logging",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "max_cursor_result_set_size",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "auto_analyze",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "max_concurrency_scaling_clusters",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "enable_case_sensitive_identifier",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                ],
                            }
                        ],
                        "ClusterSubnetGroupName": "default",
                        "VpcId": "vpc-0c1fbf2379152d7f4",
                        "AvailabilityZone": "us-east-2c",
                        "PreferredMaintenanceWindow": "wed:08:30-wed:09:00",
                        "PendingModifiedValues": {},
                        "ClusterVersion": "1.0",
                        "AllowVersionUpgrade": True,
                        "NumberOfNodes": 2,
                        "PubliclyAccessible": False,
                        "Encrypted": False,
                        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCanvmYtbNIGA5PiAY4rF"
                        "6ppg1wR3QY0f860EPUpRSaoc07UHOV4S2QLk21m5KEQm15rTE6dxVWrkXBzNabgdAsuiAo+Abur3D3y8xSZ"
                        "STMpD4e0Kn3UQ9nKw/2WWKWslNjKyzsBRSHv0jdVgg7KjtxoKAYNu/PbH4WCv2bcX+2nz8jxxDg2IOS/A6I3D"
                        "3pha9Q/FX0MMPYDKwKWw4TZ83PsZQvGWkW37TKaiGHFUpRfpuL/W8gHVD0ZJo8cK+WBxQsG5CujHlyifMQPBG"
                        "mKiFW8IeHS2evKzPAqIUlUTUA/t8t7EeCw5rnby8raUj7qWbeGqJ55d9CjcndHgaY5TZV "
                        "Amazon-Redshift\n",
                        "ClusterNodes": [
                            {
                                "NodeRole": "LEADER",
                                "PrivateIPAddress": "172.31.34.184",
                                "PublicIPAddress": "3.133.24.130",
                            },
                            {
                                "NodeRole": "COMPUTE-0",
                                "PrivateIPAddress": "172.31.35.209",
                                "PublicIPAddress": "18.220.99.27",
                            },
                            {
                                "NodeRole": "COMPUTE-1",
                                "PrivateIPAddress": "172.31.33.222",
                                "PublicIPAddress": "18.224.176.198",
                            },
                        ],
                        "ClusterRevisionNumber": "35480",
                        "Tags": [],
                        "EnhancedVpcRouting": False,
                        "IamRoles": [
                            {
                                "IamRoleArn": "arn:aws:iam::529010877102:role/service-role/"
                                "AmazonRedshift-CommandsAccessRole-20211209T063611",
                                "ApplyStatus": "in-sync",
                            }
                        ],
                        "MaintenanceTrackName": "current",
                        "ElasticResizeNumberOfNodeOptions": "[3,4,5,6,7,8]",
                        "DeferredMaintenanceWindows": [],
                        "NextMaintenanceWindowStartTime": "datetime.datetime(2022, 2, 16, 8, 30, tzinfo=tzlocal())",
                        "AvailabilityZoneRelocationStatus": "disabled",
                        "ClusterNamespaceArn": "arn:aws:redshift:us-east-2:529010877102:namespace:95b46b68-0afa-4ca9-"
                        "baf2-b6bf714431bc",
                        "TotalStorageCapacityInMegaBytes": 256000000,
                        "AquaConfiguration": {
                            "AquaStatus": "disabled",
                            "AquaConfigurationStatus": "auto",
                        },
                    }
                ]
            }
        ]
        REDSHIFT_CLIENT_MOCK.get_paginator.return_value = PAGINATOR_MOCK
        PAGINATOR_MOCK.paginate.return_value = clusters_is_present
        parameters = {
            "Parameters": [
                {
                    "ParameterName": "auto_analyze",
                    "ParameterValue": "true",
                    "Description": "Use auto analyze",
                    "Source": "engine-default",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "datestyle",
                    "ParameterValue": "ISO, MDY",
                    "Description": "Sets the display format for date and time values.",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "enable_case_sensitive_identifier",
                    "ParameterValue": "true",
                    "Description": "Preserve case sensitivity for database identifiers such as table or column names "
                    "in parser",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "enable_user_activity_logging",
                    "ParameterValue": "false",
                    "Description": "parameter for audit logging purpose",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "extra_float_digits",
                    "ParameterValue": "0",
                    "Description": "Sets the number of digits displayed for floating-point values",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "-15-2",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "max_concurrency_scaling_clusters",
                    "ParameterValue": "1",
                    "Description": "The maximum concurrency scaling clusters can be used.",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "0-10",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "max_cursor_result_set_size",
                    "ParameterValue": "default",
                    "Description": "Sets the max cursor result set size",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "0-14400000",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "query_group",
                    "ParameterValue": "default",
                    "Description": "This parameter applies a user-defined label to a group of queries that are run during the "
                    "same session..",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "require_ssl",
                    "ParameterValue": "false",
                    "Description": "require ssl for all databaseconnections",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "search_path",
                    "ParameterValue": "$user, public",
                    "Description": "Sets the schema search order for names that are not schema-qualified.",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "statement_timeout",
                    "ParameterValue": "0",
                    "Description": "Aborts any statement that takes over the specified number of milliseconds.",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "0,100-2147483647",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "use_fips_ssl",
                    "ParameterValue": "false",
                    "Description": "Use fips ssl library",
                    "Source": "engine-default",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "wlm_json_configuration",
                    "ParameterValue": '[{"auto_wlm":true}]',
                    "Description": "wlm json configuration",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
            ],
            "ResponseMetadata": {
                "RequestId": "839a0ffc-1ea6-4700-94a2-76ead2a7cb5e",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amzn-requestid": "839a0ffc-1ea6-4700-94a2-76ead2a7cb5e",
                    "content-type": "text/xml",
                    "content-length": "5806",
                    "vary": "accept-encoding",
                    "date": "Tue, 15 Feb 2022 12:08:59 GMT",
                },
                "RetryAttempts": 0,
            },
        }
        logging_disabled = {
            "LoggingEnabled": False,
            "ResponseMetadata": {
                "RequestId": "e5f58b14-923e-4be9-b463-2080843ca5c2",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amzn-requestid": "e5f58b14-923e-4be9-b463-2080843ca5c2",
                    "content-type": "text/xml",
                    "content-length": "334",
                    "date": "Wed, 02 Mar 2022 20:29:21 GMT",
                },
                "RetryAttempts": 0,
            },
        }
        REDSHIFT_CLIENT_MOCK.describe_cluster_parameters = MagicMock(
            return_value=parameters
        )
        REDSHIFT_CLIENT_MOCK.describe_logging_status.return_value = logging_disabled
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [
            build_expected_response(
                "NON_COMPLIANT",
                "redshift-cluster-1",
                annotation="Audit logging is not enforced for the cluster. "
                "Make sure to enable audit logging for the cluster. ",
            )
        ]
        assert_successful_evaluation(self, response, expected_response)

    # Unit test for if LoggingEnabled to true -- GHERKIN Scenario 3
    def test_scenario_3(self):
        clusters_is_present = [
            {
                "Clusters": [
                    {
                        "ClusterIdentifier": "redshift-cluster-1",
                        "NodeType": "ra3.4xlarge",
                        "ClusterStatus": "available",
                        "ClusterAvailabilityStatus": "Available",
                        "MasterUsername": "awsuser",
                        "DBName": "dev",
                        "Endpoint": {
                            "Address": "redshift-cluster-1.crmh4vec7kyo.us-east-2.redshift.amazonaws.com",
                            "Port": 5439,
                        },
                        "ClusterCreateTime": "datetime.datetime(2022, 1, 7, 7, 35, 2, 232000, tzinfo=tzlocal())",
                        "AutomatedSnapshotRetentionPeriod": 1,
                        "ManualSnapshotRetentionPeriod": -1,
                        "ClusterSecurityGroups": [],
                        "VpcSecurityGroups": [
                            {
                                "VpcSecurityGroupId": "sg-065ea7b9c71408f17",
                                "Status": "active",
                            }
                        ],
                        "ClusterParameterGroups": [
                            {
                                "ParameterGroupName": "myparametergroup",
                                "ParameterApplyStatus": "in-sync",
                                "ClusterParameterStatusList": [
                                    {
                                        "ParameterName": "use_fips_ssl",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "query_group",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "datestyle",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "extra_float_digits",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "search_path",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "statement_timeout",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "wlm_json_configuration",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "require_ssl",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "enable_user_activity_logging",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "max_cursor_result_set_size",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "auto_analyze",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "max_concurrency_scaling_clusters",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                    {
                                        "ParameterName": "enable_case_sensitive_identifier",
                                        "ParameterApplyStatus": "in-sync",
                                    },
                                ],
                            }
                        ],
                        "ClusterSubnetGroupName": "default",
                        "VpcId": "vpc-0c1fbf2379152d7f4",
                        "AvailabilityZone": "us-east-2c",
                        "PreferredMaintenanceWindow": "wed:08:30-wed:09:00",
                        "PendingModifiedValues": {},
                        "ClusterVersion": "1.0",
                        "AllowVersionUpgrade": True,
                        "NumberOfNodes": 2,
                        "PubliclyAccessible": False,
                        "Encrypted": False,
                        "ClusterPublicKey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCanvmYtbNIGA5PiAY4rF"
                        "6ppg1wR3QY0f860EPUpRSaoc07UHOV4S2QLk21m5KEQm15rTE6dxVWrkXBzNabgdAsuiAo+Abur3D3y8xSZ"
                        "STMpD4e0Kn3UQ9nKw/2WWKWslNjKyzsBRSHv0jdVgg7KjtxoKAYNu/PbH4WCv2bcX+2nz8jxxDg2IOS/A6I3D"
                        "3pha9Q/FX0MMPYDKwKWw4TZ83PsZQvGWkW37TKaiGHFUpRfpuL/W8gHVD0ZJo8cK+WBxQsG5CujHlyifMQPBG"
                        "mKiFW8IeHS2evKzPAqIUlUTUA/t8t7EeCw5rnby8raUj7qWbeGqJ55d9CjcndHgaY5TZV "
                        "Amazon-Redshift\n",
                        "ClusterNodes": [
                            {
                                "NodeRole": "LEADER",
                                "PrivateIPAddress": "172.31.34.184",
                                "PublicIPAddress": "3.133.24.130",
                            },
                            {
                                "NodeRole": "COMPUTE-0",
                                "PrivateIPAddress": "172.31.35.209",
                                "PublicIPAddress": "18.220.99.27",
                            },
                            {
                                "NodeRole": "COMPUTE-1",
                                "PrivateIPAddress": "172.31.33.222",
                                "PublicIPAddress": "18.224.176.198",
                            },
                        ],
                        "ClusterRevisionNumber": "35480",
                        "Tags": [],
                        "EnhancedVpcRouting": False,
                        "IamRoles": [
                            {
                                "IamRoleArn": "arn:aws:iam::529010877102:role/service-role/"
                                "AmazonRedshift-CommandsAccessRole-20211209T063611",
                                "ApplyStatus": "in-sync",
                            }
                        ],
                        "MaintenanceTrackName": "current",
                        "ElasticResizeNumberOfNodeOptions": "[3,4,5,6,7,8]",
                        "DeferredMaintenanceWindows": [],
                        "NextMaintenanceWindowStartTime": "datetime.datetime(2022, 2, 16, 8, 30, tzinfo=tzlocal())",
                        "AvailabilityZoneRelocationStatus": "disabled",
                        "ClusterNamespaceArn": "arn:aws:redshift:us-east-2:529010877102:namespace:95b46b68-0afa-4ca9-"
                        "baf2-b6bf714431bc",
                        "TotalStorageCapacityInMegaBytes": 256000000,
                        "AquaConfiguration": {
                            "AquaStatus": "disabled",
                            "AquaConfigurationStatus": "auto",
                        },
                    }
                ]
            }
        ]
        REDSHIFT_CLIENT_MOCK.get_paginator.return_value = PAGINATOR_MOCK
        PAGINATOR_MOCK.paginate.return_value = clusters_is_present
        parameters = {
            "Parameters": [
                {
                    "ParameterName": "auto_analyze",
                    "ParameterValue": "true",
                    "Description": "Use auto analyze",
                    "Source": "engine-default",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "datestyle",
                    "ParameterValue": "ISO, MDY",
                    "Description": "Sets the display format for date and time values.",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "enable_case_sensitive_identifier",
                    "ParameterValue": "true",
                    "Description": "Preserve case sensitivity for database identifiers such as table or column names in "
                    "parser",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "enable_user_activity_logging",
                    "ParameterValue": "false",
                    "Description": "parameter for audit logging purpose",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "extra_float_digits",
                    "ParameterValue": "0",
                    "Description": "Sets the number of digits displayed for floating-point values",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "-15-2",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "max_concurrency_scaling_clusters",
                    "ParameterValue": "1",
                    "Description": "The maximum concurrency scaling clusters can be used.",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "0-10",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "max_cursor_result_set_size",
                    "ParameterValue": "default",
                    "Description": "Sets the max cursor result set size",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "0-14400000",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "query_group",
                    "ParameterValue": "default",
                    "Description": "This parameter applies a user-defined label to a group of queries that are run during the "
                    "same session..",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "require_ssl",
                    "ParameterValue": "false",
                    "Description": "require ssl for all databaseconnections",
                    "Source": "user",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "search_path",
                    "ParameterValue": "$user, public",
                    "Description": "Sets the schema search order for names that are not schema-qualified.",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "statement_timeout",
                    "ParameterValue": "0",
                    "Description": "Aborts any statement that takes over the specified number of milliseconds.",
                    "Source": "engine-default",
                    "DataType": "integer",
                    "AllowedValues": "0,100-2147483647",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "use_fips_ssl",
                    "ParameterValue": "false",
                    "Description": "Use fips ssl library",
                    "Source": "engine-default",
                    "DataType": "boolean",
                    "AllowedValues": "true,false",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
                {
                    "ParameterName": "wlm_json_configuration",
                    "ParameterValue": '[{"auto_wlm":true}]',
                    "Description": "wlm json configuration",
                    "Source": "engine-default",
                    "DataType": "string",
                    "ApplyType": "static",
                    "IsModifiable": True,
                },
            ],
            "ResponseMetadata": {
                "RequestId": "839a0ffc-1ea6-4700-94a2-76ead2a7cb5e",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amzn-requestid": "839a0ffc-1ea6-4700-94a2-76ead2a7cb5e",
                    "content-type": "text/xml",
                    "content-length": "5806",
                    "vary": "accept-encoding",
                    "date": "Tue, 15 Feb 2022 12:08:59 GMT",
                },
                "RetryAttempts": 0,
            },
        }
        logging_enabled = {
            "LoggingEnabled": True,
            "ResponseMetadata": {
                "RequestId": "e5f58b14-923e-4be9-b463-2080843ca5c2",
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "x-amzn-requestid": "e5f58b14-923e-4be9-b463-2080843ca5c2",
                    "content-type": "text/xml",
                    "content-length": "334",
                    "date": "Wed, 02 Mar 2022 20:29:21 GMT",
                },
                "RetryAttempts": 0,
            },
        }
        REDSHIFT_CLIENT_MOCK.describe_cluster_parameters = MagicMock(
            return_value=parameters
        )
        REDSHIFT_CLIENT_MOCK.describe_logging_status.return_value = logging_enabled
        response = RULE.lambda_handler(build_lambda_scheduled_event(), {})
        expected_response = [
            build_expected_response(
                "COMPLIANT", "redshift-cluster-1"
            )
        ]
        assert_successful_evaluation(self, response, expected_response)


####################
# Helper Functions #
####################


def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        "configRuleName": "myrule",
        "executionRoleArn": "roleArn",
        "eventLeftScope": False,
        "invokingEvent": invoking_event,
        "accountId": "123456789012",
        "configRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan",
        "resultToken": "token",
    }
    if rule_parameters:
        event_to_return["ruleParameters"] = rule_parameters
    return event_to_return


def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        "configRuleName": "myrule",
        "executionRoleArn": "roleArn",
        "eventLeftScope": False,
        "invokingEvent": invoking_event,
        "accountId": "123456789012",
        "configRuleArn": "arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan",
        "resultToken": "token",
    }
    if rule_parameters:
        event_to_return["ruleParameters"] = rule_parameters
    return event_to_return


def build_expected_response(
    compliance_type,
    compliance_resource_id,
    compliance_resource_type=DEFAULT_RESOURCE_TYPE,
    annotation=None,
):
    if not annotation:
        return {
            "ComplianceType": compliance_type,
            "ComplianceResourceId": compliance_resource_id,
            "ComplianceResourceType": compliance_resource_type,
        }
    return {
        "ComplianceType": compliance_type,
        "ComplianceResourceId": compliance_resource_id,
        "ComplianceResourceType": compliance_resource_type,
        "Annotation": annotation,
    }


def assert_successful_evaluation(
    test_class, response, resp_expected, evaluations_count=1
):
    if isinstance(response, dict):
        test_class.assertEquals(
            resp_expected["ComplianceResourceType"], response["ComplianceResourceType"]
        )
        test_class.assertEquals(
            resp_expected["ComplianceResourceId"], response["ComplianceResourceId"]
        )
        test_class.assertEquals(
            resp_expected["ComplianceType"], response["ComplianceType"]
        )
        test_class.assertTrue(response["OrderingTimestamp"])
        if "Annotation" in resp_expected or "Annotation" in response:
            test_class.assertEquals(resp_expected["Annotation"], response["Annotation"])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(
                response_expected["ComplianceResourceType"],
                response[i]["ComplianceResourceType"],
            )
            test_class.assertEquals(
                response_expected["ComplianceResourceId"],
                response[i]["ComplianceResourceId"],
            )
            test_class.assertEquals(
                response_expected["ComplianceType"], response[i]["ComplianceType"]
            )
            test_class.assertTrue(response[i]["OrderingTimestamp"])
            if "Annotation" in response_expected or "Annotation" in response[i]:
                test_class.assertEquals(
                    response_expected["Annotation"], response[i]["Annotation"]
                )


def assert_customer_error_response(
    test_class, response, customer_error_code=None, customer_error_message=None
):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response["customerErrorCode"])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response["customerErrorMessage"])
    test_class.assertTrue(response["customerErrorCode"])
    test_class.assertTrue(response["customerErrorMessage"])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response["internalErrorMessage"])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response["internalErrorDetails"])


def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string",
        }
    }
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)


##################
# Common Testing #
##################


class TestStsErrors(unittest.TestCase):
    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(
            side_effect=ClientError(
                {"Error": {"Code": "unknown-code", "Message": "unknown-message"}},
                "operation",
            )
        )
        response = RULE.lambda_handler(build_lambda_configurationchange_event("{}"), {})
        assert_customer_error_response(self, response, "InternalError", "InternalError")

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "access-denied"}},
                "operation",
            )
        )
        response = RULE.lambda_handler(build_lambda_configurationchange_event("{}"), {})
        assert_customer_error_response(
            self,
            response,
            "AccessDenied",
            "AWS Config does not have permission to assume the IAM role.",
        )


if __name__ == "__main__":
    unittest.main()
