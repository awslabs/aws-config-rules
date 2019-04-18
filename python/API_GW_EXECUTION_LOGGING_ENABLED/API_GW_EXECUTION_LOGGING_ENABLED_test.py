import sys
import unittest
try:
    from unittest.mock import MagicMock
except ImportError:
    from mock import MagicMock
import json
import botocore

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::ApiGateway::RestApi'

#############
# Main Code #
#############

CONFIG_CLIENT_MOCK = MagicMock()
STS_CLIENT_MOCK = MagicMock()

class Boto3Mock():
    @staticmethod
    def client(client_name, *args, **kwargs):
        if client_name == 'config':
            return CONFIG_CLIENT_MOCK
        if client_name == 'sts':
            return STS_CLIENT_MOCK
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

RULE = __import__('API_GW_EXECUTION_LOGGING_ENABLED')

class ParameterTest(unittest.TestCase):

    invoking_event_parameter_test_1 = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'ERROR', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'ERROR', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
    invoking_event_parameter_test_2 = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'INFO', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'INFO', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
    invoking_event_non_compliant = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'INFO', 'updatedValue': 'OFF', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'OFF', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})

     #Scenario 1: Rule Parameter is invalid
    def test_invalid_param_value(self):
        rule_parameters = '{"loggingLevel": "SOMETHING"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_parameter_test_1, rule_parameters), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    def test_invalid_parameter_values2(self):
        rule_parameters = '{"loggingLevel": "ERROR,NO"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_parameter_test_1, rule_parameters), {})
        assert_customer_error_response(self, response, 'InvalidParameterValueException')

    #Scenario 2: Non Compliant
    def test_no_parameter_non_compliant(self):
        rule_parameters = '{}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_non_compliant, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage', 'API Stage: test doesn\'t have required logging level enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3: Compliant
    def test_no_parameter_complaint_1(self):
        rule_parameters = '{}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_parameter_test_1, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_no_parameter_compliant_2(self):
        rule_parameters = '{}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(self.invoking_event_parameter_test_2, rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)


class LoggingLevelTest(unittest.TestCase):
    rule_parameters = '{"loggingLevel": "ERROR,INFO"}'

    #Scenario 2: Non compliant for Resource Type AWS::ApiGateway::Stage
    def test_logging_level_overriden_off(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.~1test~1{proxy}/GET': {'previousValue': None, 'updatedValue': {'metricsEnabled': False, 'loggingLevel': 'OFF', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}, 'changeType': 'CREATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Apr 10, 2019 7:29:25 AM', 'updatedValue': 'Apr 13, 2019 6:06:01 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': 'tex2hz', 'stageName': 'limit', 'cacheClusterEnabled': False, 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'~1test~1{proxy}/GET': {'metricsEnabled': False, 'loggingLevel': 'OFF', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}, '*/*': {'metricsEnabled': False, 'loggingLevel': 'INFO', 'dataTraceEnabled': True, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': False, 'createdDate': 'Feb 21, 2019 8:10:53 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:06:01 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:06:02.230Z', 'configurationStateId': 1555178762230, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit', 'resourceName': 'limit', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2019-02-21T08:10:53.890Z'}, 'notificationCreationTime': '2019-04-13T18:06:02.935Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/limit', 'AWS::ApiGateway::Stage', 'API Stage: limit doesn\'t have required logging level enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_info_non_compliant(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'INFO', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'INFO', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        rule_parameters = '{"loggingLevel": "ERROR"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage', 'API Stage: test doesn\'t have required logging level enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_error_non_compliant(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'ERROR', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'ERROR', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        rule_parameters = '{"loggingLevel": "INFO"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage', 'API Stage: test doesn\'t have required logging level enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3: Compliant for Resource Type AWS::ApiGateway::Stage
    def test_logging_level_info(self):
        invoking_event = '{ "configurationItem": {"relatedEvents": [], "relationships": [{"resourceId": "arn:aws:apigateway:us-east-1::/restapis/asdf567gh", "resourceName": "cache-edge", "resourceType": "AWS::ApiGateway::RestApi", "name": "Is contained in "}], "configuration": {"deploymentId": "jtemac", "stageName": "test",  "cacheClusterSize": "0.5", "cacheClusterStatus": "AVAILABLE", "methodSettings": {"*/*": { "loggingLevel": "INFO",   "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"}, "~1elastic~1dug/GET": { "loggingLevel": "INFO",  "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"}}, "createdDate": "Nov 23, 2018 4:15:40 AM", "lastUpdatedDate": "Nov 23, 2018 4:59:33 AM"}, "supplementaryConfiguration": {}, "tags": {}, "configurationItemVersion": "1.3", "configurationItemCaptureTime": "2019-03-20T04:54:41.388Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test", "resourceName": "test", "ARN": "arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test", "awsRegion": "us-east-1", "availabilityZone": "Not Applicable", "configurationStateMd5Hash": "", "resourceCreationTime": "2018-11-23T04:15:40.744Z"}, "notificationCreationTime": "2019-04-11T10:46:59.236Z", "messageType": "ConfigurationItemChangeNotification", "recordVersion": "1.3"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_error(self):
        invoking_event = '{ "configurationItem": {"relatedEvents": [], "relationships": [{"resourceId": "arn:aws:apigateway:us-east-1::/restapis/asdf567gh", "resourceName": "cache-edge", "resourceType": "AWS::ApiGateway::RestApi", "name": "Is contained in "}], "configuration": {"deploymentId": "jtemac", "stageName": "test",  "cacheClusterSize": "0.5", "cacheClusterStatus": "AVAILABLE", "methodSettings": {"*/*": { "loggingLevel": "ERROR",   "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"}, "~1elastic~1dug/GET": { "loggingLevel": "ERROR",  "unauthorizedCacheControlHeaderStrategy": "SUCCEED_WITH_RESPONSE_HEADER"}}, "createdDate": "Nov 23, 2018 4:15:40 AM", "lastUpdatedDate": "Nov 23, 2018 4:59:33 AM"}, "supplementaryConfiguration": {}, "tags": {}, "configurationItemVersion": "1.3", "configurationItemCaptureTime": "2019-03-20T04:54:41.388Z", "awsAccountId": "123456789012", "configurationItemStatus": "ResourceDiscovered", "resourceType": "AWS::ApiGateway::Stage", "resourceId": "arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test", "resourceName": "test", "ARN": "arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test", "awsRegion": "us-east-1", "availabilityZone": "Not Applicable", "configurationStateMd5Hash": "", "resourceCreationTime": "2018-11-23T04:15:40.744Z"}, "notificationCreationTime": "2019-04-11T10:46:59.236Z", "messageType": "ConfigurationItemChangeNotification", "recordVersion": "1.3"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/asdf567gh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_info_compliant(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'INFO', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'INFO', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        rule_parameters = '{"loggingLevel": "INFO"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_logging_level_error_compliant(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.methodSettings.*/*.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'ERROR', 'changeType': 'UPDATE'}, 'Configuration.lastUpdatedDate': {'previousValue': 'Dec 12, 2018 9:01:20 AM', 'updatedValue': 'Apr 13, 2019 6:04:37 PM', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh', 'resourceName': 'resource1', 'resourceType': 'AWS::ApiGateway::RestApi', 'name': 'Is contained in '}], 'configuration': {'deploymentId': '0r280l', 'stageName': 'test', 'cacheClusterEnabled': False, 'cacheClusterSize': '0.5', 'cacheClusterStatus': 'NOT_AVAILABLE', 'methodSettings': {'*/*': {'metricsEnabled': False, 'loggingLevel': 'ERROR', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0, 'cachingEnabled': False, 'cacheTtlInSeconds': 300, 'cacheDataEncrypted': False, 'requireAuthorizationForCacheControl': True, 'unauthorizedCacheControlHeaderStrategy': 'SUCCEED_WITH_RESPONSE_HEADER'}}, 'tracingEnabled': True, 'createdDate': 'Dec 4, 2018 10:09:21 AM', 'lastUpdatedDate': 'Apr 13, 2019 6:04:37 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T18:04:37.523Z', 'configurationStateId': 1555178677523, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGateway::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2018-12-04T10:09:21.128Z'}, 'notificationCreationTime': '2019-04-13T18:04:37.840Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        rule_parameters = '{"loggingLevel": "ERROR"}'
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), {})
        print(response)
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/restapis/abcd123fgh/stages/test', 'AWS::ApiGateway::Stage'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 2: Non Compliant for Resource Type AWS::ApiGatewayV2::Stage
    def test_apiv2_create_loglevel_with_off(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {}, 'changeType': 'CREATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu', 'resourceName': 'My Chat API-WebSocket', 'resourceType': 'AWS::ApiGatewayV2::Api', 'name': 'Is contained in '}], 'configuration': {'stageName': 'config4', 'deploymentId': 'j8k0k8', 'defaultRouteSettings': {'detailedMetricsEnabled': False, 'loggingLevel': 'OFF', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0}, 'routeSettings': {}, 'stageVariables': {}, 'createdDate': 'Apr 13, 2019 5:18:47 PM', 'lastUpdatedDate': 'Apr 13, 2019 5:18:47 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T17:18:47.488Z', 'configurationStateId': 1555175927488, 'awsAccountId': '123456789012', 'configurationItemStatus': 'ResourceDiscovered', 'resourceType': 'AWS::ApiGatewayV2::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/config4', 'resourceName': 'config4', 'ARN': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/config4', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2019-04-13T17:18:47.262Z'}, 'notificationCreationTime': '2019-04-13T17:18:47.730Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/config4', 'AWS::ApiGatewayV2::Stage', 'API Stage: config4 doesn\'t have required logging level enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_apiv2_change_loglevel_to_off(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.defaultRouteSettings.loggingLevel': {'previousValue': 'INFO', 'updatedValue': 'OFF', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu', 'resourceName': 'My Chat API-WebSocket', 'resourceType': 'AWS::ApiGatewayV2::Api', 'name': 'Is contained in '}], 'configuration': {'stageName': 'test', 'deploymentId': 'fncu8d', 'defaultRouteSettings': {'detailedMetricsEnabled': False, 'loggingLevel': 'OFF', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0}, 'routeSettings': {}, 'stageVariables': {}, 'createdDate': 'Apr 13, 2019 5:18:04 PM', 'lastUpdatedDate': 'Apr 13, 2019 5:18:04 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T17:18:24.496Z', 'configurationStateId': 1555175904496, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGatewayV2::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2019-04-13T17:18:04.479Z'}, 'notificationCreationTime': '2019-04-13T17:18:24.828Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'AWS::ApiGatewayV2::Stage', 'API Stage: test doesn\'t have required logging level enabled.'))
        assert_successful_evaluation(self, response, resp_expected)

    #Scenario 3: Compliant for Resource Type AWS::ApiGatewayV2::Stage
    def test_apiv2_change_loglevel_to_info(self):
        invoking_event = json.dumps({'configurationItemDiff': {'changedProperties': {'Configuration.defaultRouteSettings.loggingLevel': {'previousValue': 'OFF', 'updatedValue': 'INFO', 'changeType': 'UPDATE'}}, 'changeType': 'UPDATE'}, 'configurationItem': {'relatedEvents': [], 'relationships': [{'resourceId': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu', 'resourceName': 'My Chat API-WebSocket', 'resourceType': 'AWS::ApiGatewayV2::Api', 'name': 'Is contained in '}], 'configuration': {'stageName': 'test', 'deploymentId': 'fncu8d', 'defaultRouteSettings': {'detailedMetricsEnabled': False, 'loggingLevel': 'INFO', 'dataTraceEnabled': False, 'throttlingBurstLimit': 5000, 'throttlingRateLimit': 10000.0}, 'routeSettings': {}, 'stageVariables': {}, 'createdDate': 'Apr 13, 2019 5:18:04 PM', 'lastUpdatedDate': 'Apr 13, 2019 5:18:04 PM'}, 'supplementaryConfiguration': {}, 'tags': {}, 'configurationItemVersion': '1.3', 'configurationItemCaptureTime': '2019-04-13T17:18:21.693Z', 'configurationStateId': 1555175901693, 'awsAccountId': '123456789012', 'configurationItemStatus': 'OK', 'resourceType': 'AWS::ApiGatewayV2::Stage', 'resourceId': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'resourceName': 'test', 'ARN': 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'awsRegion': 'us-east-1', 'availabilityZone': 'Not Applicable', 'configurationStateMd5Hash': '', 'resourceCreationTime': '2019-04-13T17:18:04.479Z'}, 'notificationCreationTime': '2019-04-13T17:18:21.899Z', 'messageType': 'ConfigurationItemChangeNotification', 'recordVersion': '1.3'})
        RULE.ASSUME_ROLE_MODE = False
        response = RULE.lambda_handler(build_lambda_configurationchange_event(invoking_event, self.rule_parameters), {})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', 'arn:aws:apigateway:us-east-1::/apis/qwert123yu/stages/test', 'AWS::ApiGatewayV2::Stage'))
        assert_successful_evaluation(self, response, resp_expected)


####################
# Helper Functions #
####################

def build_lambda_configurationchange_event(invoking_event, rule_parameters=None):
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_lambda_scheduled_event(rule_parameters=None):
    invoking_event = '{"messageType":"ScheduledNotification","notificationCreationTime":"2017-12-23T22:11:18.158Z"}'
    event_to_return = {
        'configRuleName':'myrule',
        'executionRoleArn':'roleArn',
        'eventLeftScope': False,
        'invokingEvent': invoking_event,
        'accountId': '123456789012',
        'configRuleArn': 'arn:aws:config:us-east-1:123456789012:config-rule/config-rule-8fngan',
        'resultToken':'token'
    }
    if rule_parameters:
        event_to_return['ruleParameters'] = rule_parameters
    return event_to_return

def build_expected_response(compliance_type, compliance_resource_id, compliance_resource_type=DEFAULT_RESOURCE_TYPE, annotation=None):
    if not annotation:
        return {
            'ComplianceType': compliance_type,
            'ComplianceResourceId': compliance_resource_id,
            'ComplianceResourceType': compliance_resource_type
            }
    return {
        'ComplianceType': compliance_type,
        'ComplianceResourceId': compliance_resource_id,
        'ComplianceResourceType': compliance_resource_type,
        'Annotation': annotation
        }

def assert_successful_evaluation(test_class, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        test_class.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        test_class.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        test_class.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        test_class.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            test_class.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        test_class.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            test_class.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            test_class.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            test_class.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            test_class.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                test_class.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(test_class, response, customer_error_code=None, customer_error_message=None):
    if customer_error_code:
        test_class.assertEqual(customer_error_code, response['customerErrorCode'])
    if customer_error_message:
        test_class.assertEqual(customer_error_message, response['customerErrorMessage'])
    test_class.assertTrue(response['customerErrorCode'])
    test_class.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        test_class.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        test_class.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    STS_CLIENT_MOCK.reset_mock(return_value=True)
    STS_CLIENT_MOCK.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        RULE.ASSUME_ROLE_MODE = True
        STS_CLIENT_MOCK.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = RULE.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')
