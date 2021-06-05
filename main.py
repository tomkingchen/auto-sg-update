# app.py
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import random
import string
import ipaddress
import time
from bs4 import BeautifulSoup
import boto3
from botocore.exceptions import ClientError

def create_sg(vpc_id):
  ec2 = boto3.client('ec2')
  sg_name_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))
  sg_name_prefix = 'sec-workspace1-'
  security_group_name = sg_name_prefix + sg_name_suffix
  
  try:
    response = ec2.create_security_group(GroupName=security_group_name,
                                         Description='WorkspaceOne Security Group',
                                         VpcId=vpc_id)
    security_group_id = response['GroupId']
    print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))
    return security_group_id
  except ClientError as e:
    print(e)
    return None

def add_sg_ingress_rule(security_group_id, workspace_ip):
  ec2 = boto3.client('ec2')
  try:
    data = ec2.authorize_security_group_ingress(
      GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 1999,
             'ToPort': 1999,
             'IpRanges': [{'CidrIp': workspace_ip}]}
        ])
  except ClientError as e:
    print(e)
    return None

def dettach_sgs(ec2_id):
  ec2 = boto3.resource('ec2')
  try:
    instance = ec2.Instance(ec2_id)
    sg_ids = [sg['GroupId'] for sg in instance.security_groups]     # Get ids of all SG attached to the instance
    instance.modify_attribute(Groups=['sg-123456789abcdef'])        # Dettach all existing SGs
    print('Successfully dettached existing security groups')
    for sg_id in sg_ids:
      sec_group = ec2.SecurityGroup(sg_id)
      sec_group.delete()
      print('Successfully deleted security group %s' % (sg_id))
  except ClientError as e:
    print(e)

def delete_sgs():
  ec2 = boto3.resource('ec2')

def attach_sgs(ec2_id, sg_ids):
  ec2 = boto3.resource('ec2')
  try:
    instance = ec2.Instance(ec2_id)
    instance.modify_attribute(Groups=sg_ids)
    print('Successfully attached security groups to instance.')
  except ClientError as e:
    print(e)

def validate_ip(workspace_ip):
  try:
    cidr_ip = ipaddress.ip_network(workspace_ip)
    workspace_ip = str(cidr_ip)
    if workspace_ip.find('/') == -1:
      workspace_ip += '/32'
    return workspace_ip
  except:
    return -1

def main():
  options = Options()
  options.headless = True
  driver = webdriver.Chrome('/usr/bin/chromedriver', options=options)
  driver.get('https://kb.vmware.com/s/article/2960995')
  time.sleep(5)
  page = driver.page_source                                   # Get the Javascript rendered HTML Page

  soup = BeautifulSoup(page, 'html.parser')
  page_content = soup.find(id='article_content')
  page_containers = page_content.find_all('div', class_='container')
  ip_list_content = page_containers[1].find('div', class_ = 'content')
  driver.quit()
  ip_list = []
  for ip_addr in ip_list_content.find_all('li'):
    ip_list.append(ip_addr.text.strip())
  # Remove country prefixes
  ip_list = list(map(lambda x: x.replace('USA: ','').replace('UK: ','').replace('SG: ','').replace('CA: ', '').replace('DE: ', '').replace('UK: ', '').replace('USA: ', '').replace(' /', '/').replace('/ ', '/'),ip_list))

  # Initialize values for SG creation
  vpc_id = 'vpc-123456789abcdef'
  sg_rules_len = 0
  uf_secgroups = []
  # Create new sg
  sg_id = create_sg(vpc_id)
  uf_secgroups.append(sg_id)
  
  # Attach sg to UF instance
  for ip in ip_list:
    ip_addr = validate_ip(ip)
    if ip_addr != -1:
      if sg_rules_len < 100:
        # Add rule to sg
        add_sg_ingress_rule(sg_id, ip_addr)
        sg_rules_len += 1
      else:
        sg_rules_len = 0
        # Create new sg
        sg_id = create_sg(vpc_id)
        uf_secgroups.append(sg_id)
        # Add rule to sg
        add_sg_ingress_rule(sg_id, ip_addr)
        sg_rules_len += 1

  # Attach sg to UF instance
  instance_id = 'i-0123456789abcdef'
  dettach_sgs(instance_id)                    # Detach and cleanup existing SGs
  attach_sgs(instance_id, uf_secgroups)
 

if __name__ == "__main__":
    main()