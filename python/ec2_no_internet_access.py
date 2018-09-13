#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Ensures that there is no internet connectivity
# Description: checks the given resource on potential internet access
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance, EC2:VPC, EC2:RouteTable, EC2:Subnet, EC2:NetworkInterface
# Optional Parameter: None
# Example Value: N/A
#
# Requires additional AWS Config permissions for GetResourceConfigHistory

from __future__ import print_function

import json
import boto3

aws_config = boto3.client('config')
aws_ec2 = boto3.client('ec2')

# this is a utility class for parsing config rules events. RaiseInternetConnectivity inherhits from it
class ConfigRule:
  """Base class for implementing a custom config rule in AWS Lambda"""
  
  def __init__(self, configurationItem):
    self.configurationItem = configurationItem
    self.relationships = configurationItem['relationships']
   
  def evaluate_compliance(self, configurationItem=None):
    """Actual evaluation logic will be implemented here"""
    return 'NOT_APPLICABLE' 

  def get_relationship(self, relationships, id):
    for i in relationships:
       if i['resourceId'] == id:
         return i
    return None
  
  def find_relationships_by_type(self, type, relationships=None):
    if not relationships:
      relationships = self.relationships
    
    result = []
    for i in relationships:
       if i['resourceType'] == type:
         result.append(i)
    return result  
    
  def get_related_configuration_item(self, relationship):
    result = aws_config.get_resource_config_history(
      resourceType=relationship['resourceType'],
      resourceId=relationship['resourceId'],
      limit=1,
    )
    item = result['configurationItems'][0]
    
    if item.has_key('configuration'):
      item['configuration'] = json.loads(item['configuration'])
    return item
    
  def put_evaluations(self, compliance, resultToken):
    aws_config.put_evaluations(
      Evaluations=[
          {
            'ComplianceResourceType': self.configurationItem['resourceType'],
            'ComplianceResourceId': self.configurationItem['resourceId'],
            'ComplianceType': compliance,
            'OrderingTimestamp': self.configurationItem['configurationItemCaptureTime']
          },
      ],
      ResultToken=resultToken
    )


class RaiseInternetConnectivity(ConfigRule):
  """
    Class for checking given resources for potential internet access.

    Supported types are: VPC, RouteTable, Subnet, Instance, NetworkInterface

    Implemented checks are:

    VPC: Check for attached IGW
    RouteTable: Check for route to an IGW
    Subnet: check if public ip address mapping is enabled, check if assigned route table has a route to an IGW
    Instance: check if instance has a public ip assigned
    NetworkInterface: check if interface has a public ip assigned
  """
  def evaluate_compliance(self, configurationItem=None):
    if not configurationItem:
      configurationItem = self.configurationItem
    relationships = self.relationships
    
    if configurationItem['configurationItemStatus'] == 'ResourceDeleted':
      return 'NOT_APPLICABLE'
      
    # check if VPC has an internet gateway attached
    if configurationItem['resourceType'] == 'AWS::EC2::VPC':
      if self.find_relationships_by_type('AWS::EC2::InternetGateway'):
        return 'NON_COMPLIANT'
      else:
        return 'COMPLIANT'

    # check if the route table has a rule with an internet gateway
    if configurationItem['resourceType'] == 'AWS::EC2::RouteTable':
      return self.evaluate_route_table(configurationItem)
      
    # check the subnet for potential internet accessibility 
    if configurationItem['resourceType'] == "AWS::EC2::Subnet":
      # check if subnet has configured public ip assignment as default
      if configurationItem['configuration']['mapPublicIpOnLaunch']:
        return 'NON_COMPLIANT'
        
      # check if subnet has a route to an internet gateway
      try: 
        route_table = self.get_related_configuration_item(self.find_relationships_by_type('AWS::EC2::RouteTable').pop())
      except:
        # no routing table associated, get main routing table of VPC
        vpc = self.get_related_configuration_item(self.find_relationships_by_type('AWS::EC2::VPC').pop())
        route_tables = self.find_relationships_by_type('AWS::EC2::RouteTable', vpc['relationships'])
        for i in route_tables:
          r = self.get_related_configuration_item(i)
          if r['configuration']['associations'][0]['main']:
            route_table = r
            break
        else:
          raise Exception('Main route table not found', vpc)
         
      # check if assigned route table has a rule with an internet gateway
      return self.evaluate_route_table(route_table)
    
    # check if the instance has a public ip assigned
    if configurationItem['resourceType'] == 'AWS::EC2::Instance':
      if configurationItem['configuration']['publicIpAddress']:
        return 'NON_COMPLIANT'
      return 'COMPLIANT'
      
    # check if network interface has a public ip associated
    if configurationItem['resourceType'] == 'AWS::EC2::NetworkInterface':
      for i in configurationItem['configuration']['privateIpAddresses']:
        if i['association']:
          return 'NON_COMPLIANT'
      return 'COMPLIANT'
      
    return 'NOT_APPLICABLE'
  
  def evaluate_route_table(self, route_table):
    for route in route_table['configuration']['routes']:
      if route['gatewayId'] and route['gatewayId'].startswith('igw-'):
        return 'NON_COMPLIANT'
    return 'COMPLIANT'  


def lambda_handler(event, context):
  try:
    invokingEvent = json.loads(event['invokingEvent'])
    configurationItem = invokingEvent['configurationItem']
  except:
    raise Exception('Could not load configuration item', event)
 
  try:
    rule = RaiseInternetConnectivity(configurationItem)
  except:
    raise Exception('Could not process configuration item', configurationItem)
  
  compliance = rule.evaluate_compliance()
 
  print('Compliance evaluation for %s: %s' % (configurationItem['resourceId'], compliance))
 
  # inform config rules about our evaluation result
  rule.put_evaluations(compliance, event['resultToken'])
