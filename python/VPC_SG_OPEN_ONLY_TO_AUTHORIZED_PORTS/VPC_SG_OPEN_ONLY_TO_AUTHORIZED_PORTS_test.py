import sys
import unittest
try:
    from unittest.mock import MagicMock, patch, ANY
except ImportError:
    import mock
    from mock import MagicMock, patch, ANY
import botocore
from botocore.exceptions import ClientError

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
DEFAULT_RESOURCE_TYPE = 'AWS::EC2::SecurityGroup'

#############
# Main Code #
#############

config_client_mock = MagicMock()
sts_client_mock = MagicMock()

class Boto3Mock():
    def client(self, client_name, *args, **kwargs):
        if client_name == 'config':
            return config_client_mock
        elif client_name == 'sts':
            return sts_client_mock
        else:
            raise Exception("Attempting to create an unknown client")

sys.modules['boto3'] = Boto3Mock()

rule = __import__('VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS')

class SampleTest(unittest.TestCase):
    
    # Scenario 1: Security group in exception list
    def test_sg_in_list(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[{"cidrIpv6":"::/0"}],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[{"cidrIpv6":"::/0"}],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[{"cidrIpv6":"::/0"}],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[{"cidrIpv6":"::/0"}],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{"authorizedTCPPorts": "443","authorizedUDPPorts": "80","exceptionList": "sg-01"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 2: Security group has no port open to 0.0.0.0/0
    def test_sg_no_port_open_to_world(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"10.0.0.0/0"}],"ipRanges":["10.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"11.0.0.0/0"}],"ipRanges":["11.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"15.0.0.0/0"}],"ipRanges":["15.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"25.25.0.0/0"}],"ipRanges":["25.25.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{"authorizedTCPPorts": "443","authorizedUDPPorts": "80","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    def test_sg_no_port_open_to_world_and_no_authorized_tcp(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"11.0.0.0/0"}],"ipRanges":["11.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"15.0.0.0/0"}],"ipRanges":["15.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"25.25.0.0/0"}],"ipRanges":["25.25.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='No open TCP port is authorized via the authorizedTCPPorts parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    def test_sg_no_port_open_to_world_and_no_authorized_udp(self):
        invoking_event = '{"configurationItemDiff":null,"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":15000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":15000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]},{"fromPort":80,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":80,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"11.0.0.0/0"}],"ipRanges":["11.0.0.0/0"]},{"fromPort":11000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":11000,"userIdGroupPairs":[],"ipv4Ranges":[],"ipRanges":[]},{"fromPort":0,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":65535,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"15.0.0.0/0"}],"ipRanges":["15.0.0.0/0"]},{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"25.25.0.0/0"}],"ipRanges":["25.25.0.0/0"]},{"fromPort":443,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":443,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"52.95.75.1/32"}],"ipRanges":["52.95.75.1/32"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemVersion":"1.3","configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification","recordVersion":"1.3"}'
        rule_parameters = '{}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='No open UDP port is authorized via the authorizedUDPPorts parameter.'))
        assert_successful_evaluation(self, response, resp_expected)
    # Scenario 3: Open UDP port range not in authorizedUDPPorts
    def test_one_udp_open_not_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTCPPorts": "443","authorizedUDPPorts": "80","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='No all open UDP port (10000) is not in range of the authorizedUDPPorts parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 4: Open TCP port range not in authorizedTCPPorts
    def test_one_tcp_open_not_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":12000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTCPPorts": "443","authorizedUDPPorts": "80","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('NON_COMPLIANT', resource_id, annotation='No all open TCP port (10000-12000) is not in range of the authorizedTCPPorts parameter.'))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 5: Open UDP port range in authorizedUDPPorts
    def test_one_udp_open_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTCPPorts": "443","authorizedUDPPorts": "10000","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 6: Open TCP port range in authorizedTCPPorts
    def test_one_tcp_open_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":10000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTCPPorts": "10000","authorizedUDPPorts": "80","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
        assert_successful_evaluation(self, response, resp_expected)

    # Scenario 7: Both open TCP and UDP ports in authorised ports
    def test_tcp_and_udp_open_authorized(self):
        invoking_event = '{"configurationItem":{"relatedEvents":[],"relationships":[{"resourceId":"vpc-4540bc2d","resourceName":null,"resourceType":"AWS::EC2::VPC","name":"IscontainedinVpc"}],"configuration":{"description":"testgroupforconfig","groupName":"testconfig","ipPermissions":[{"fromPort":10000,"ipProtocol":"tcp","ipv6Ranges":[],"prefixListIds":[],"toPort":20000,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}, {"fromPort":80,"ipProtocol":"udp","ipv6Ranges":[],"prefixListIds":[],"toPort":100,"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"0.0.0.0/0"}],"ipRanges":["0.0.0.0/0"]}],"ownerId":"970012433126","groupId":"sg-01","ipPermissionsEgress":[{"ipProtocol":"-1","ipv6Ranges":[],"prefixListIds":[],"userIdGroupPairs":[],"ipv4Ranges":[{"cidrIp":"43.0.0.0/0"}],"ipRanges":["43.0.0.0/0"]}],"tags":[],"vpcId":"vpc-4540bc2d"},"supplementaryConfiguration":{},"tags":{},"configurationItemCaptureTime":"2018-09-07T05:26:45.866Z","configurationStateId":1536298470560,"awsAccountId":"970012433126","configurationItemStatus":"OK","resourceType":"AWS::EC2::SecurityGroup","resourceId":"sg-01","resourceName":"testconfig","ARN":"arn:aws:ec2:ap-south-1:970012433126:security-group/sg-005ce5b72094fba04","awsRegion":"ap-south-1","availabilityZone":"NotApplicable","configurationStateMd5Hash":"","resourceCreationTime":null},"notificationCreationTime":"2018-09-07T09:52:39.472Z","messageType":"ConfigurationItemChangeNotification"}'
        rule_parameters = '{"authorizedTCPPorts": "10000-20000","authorizedUDPPorts": "80-100","exceptionList": "sg-02"}'
        resource_id = "sg-01"
        response = rule.lambda_handler(build_lambda_configurationchange_event(invoking_event, rule_parameters), context={})
        resp_expected = []
        resp_expected.append(build_expected_response('COMPLIANT', resource_id))
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

def assert_successful_evaluation(testClass, response, resp_expected, evaluations_count=1):
    if isinstance(response, dict):
        testClass.assertEquals(resp_expected['ComplianceType'], response['ComplianceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceType'], response['ComplianceResourceType'])
        testClass.assertEquals(resp_expected['ComplianceResourceId'], response['ComplianceResourceId'])
        testClass.assertTrue(response['OrderingTimestamp'])
        if 'Annotation' in resp_expected or 'Annotation' in response:
            testClass.assertEquals(resp_expected['Annotation'], response['Annotation'])
    elif isinstance(response, list):
        testClass.assertEquals(evaluations_count, len(response))
        for i, response_expected in enumerate(resp_expected):
            testClass.assertEquals(response_expected['ComplianceType'], response[i]['ComplianceType'])
            testClass.assertEquals(response_expected['ComplianceResourceType'], response[i]['ComplianceResourceType'])
            testClass.assertEquals(response_expected['ComplianceResourceId'], response[i]['ComplianceResourceId'])
            testClass.assertTrue(response[i]['OrderingTimestamp'])
            if 'Annotation' in response_expected or 'Annotation' in response[i]:
                testClass.assertEquals(response_expected['Annotation'], response[i]['Annotation'])

def assert_customer_error_response(testClass, response, customerErrorCode=None, customerErrorMessage=None):
    if customerErrorCode:
        testClass.assertEqual(customerErrorCode, response['customerErrorCode'])
    if customerErrorMessage:
        testClass.assertEqual(customerErrorMessage, response['customerErrorMessage'])
    testClass.assertTrue(response['customerErrorCode'])
    testClass.assertTrue(response['customerErrorMessage'])
    if "internalErrorMessage" in response:
        testClass.assertTrue(response['internalErrorMessage'])
    if "internalErrorDetails" in response:
        testClass.assertTrue(response['internalErrorDetails'])

def sts_mock():
    assume_role_response = {
        "Credentials": {
            "AccessKeyId": "string",
            "SecretAccessKey": "string",
            "SessionToken": "string"}}
    sts_client_mock.reset_mock(return_value=True)
    sts_client_mock.assume_role = MagicMock(return_value=assume_role_response)

##################
# Common Testing #
##################

class TestStsErrors(unittest.TestCase):

    def test_sts_unknown_error(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'unknown-code', 'Message': 'unknown-message'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'InternalError', 'InternalError')

    def test_sts_access_denied(self):
        rule.ASSUME_ROLE_MODE = True
        sts_client_mock.assume_role = MagicMock(side_effect=botocore.exceptions.ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'access-denied'}}, 'operation'))
        response = rule.lambda_handler(build_lambda_configurationchange_event('{}'), {})
        assert_customer_error_response(
            self, response, 'AccessDenied', 'AWS Config does not have permission to assume the IAM role.')