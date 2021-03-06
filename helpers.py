import sys
import time

def ssm_make_document(ssm_client, ssm_command, ssm_document_name, ssm_document_body):
  time.sleep(1)
  return ssm_client.create_document(Content=ssm_document_body, Name=ssm_document_name, DocumentType='Command', DocumentFormat='JSON')

def ssm_exec_document(ssm_client, instance_id, ssm_document_name):
  time.sleep(1)
  return ssm_client.send_command(InstanceIds=[ instance_id ], DocumentName=ssm_document_name)

def stop_instance(ec2_client, instance_id):
  time.sleep(1)
  return ec2_client.stop_instances(InstanceIds=[ instance_id ])

def image_instance(ec2_client, instance_id):
  time.sleep(1)
  return ec2_client.create_image(Description=instance_id, InstanceId=instance_id, Name=instance_id, NoReboot=True)

def get_running_instances(ec2_client):
  return ec2_client.describe_instances(Filters=[ {'Name': 'instance-state-name', 'Values': [ 'running' ]} ])['Reservations'][0]['Instances']

def get_buckets(s3_client):
  return s3_client.list_buckets()['Buckets']

def check_aws_roles(role_name):
  if (
    role_name != 'AWSServiceRoleForOrganizations' and
    role_name != 'AWSServiceRoleForAutoScaling'
  ):
    return True
  else:
    return False

def verify_admin_user(iam_client, user_name):
  user_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
  user_admin = False
  for policy in user_policies:
    if policy['PolicyName'] == "AdministratorAccess":
      user_admin = True
  if not user_admin:
    groups = iam_client.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
      group_policies = iam_client.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
      for policy in group_policies:
        if policy['PolicyName'] == "AdministratorAccess":
          user_admin = True
  if user_admin:
    return 'Current aws profile user keys are valid.'
  else:
    print("In order to run this code, please add the AdministratorAccess managed IAM policy to your current user.")
    sys.exit(1)


def get_policy_arn(account_id, policy_name):
  return 'arn:aws:iam::' + account_id + ':policy/' + policy_name


def save_logs(logs, logs_name):
  for log in logs:
    print(logs_name + str(log))


def create_nacl_entry(ec2_client, egress, nacl_id, rule_number):
  return ec2_client.create_network_acl_entry(
    CidrBlock='0.0.0.0/0',
    Egress=egress,
    Protocol='-1',
    RuleAction='deny',
    RuleNumber=rule_number,
    NetworkAclId=nacl_id
  )


def delete_nacl_entry(ec2_client, egress, nacl_id, rule_number):
  return ec2_client.delete_network_acl_entry(
    Egress=egress,
    RuleNumber=rule_number,
    NetworkAclId=nacl_id
  )


def create_deny_policy(iam_client, account_id, policy_name):
  try:
    deny_policy = iam_client.create_policy(
      PolicyName=policy_name,
      Description=policy_name,
      PolicyDocument='{"Version":"2012-10-17","Statement":[{"Sid":"' + policy_name + '","Effect":"Deny","Action":"*","Resource":"*"}]}'
    )['Policy']
    return deny_policy
  except Exception as err:
    deny_policy = {}
    deny_policy['Arn'] = get_policy_arn(account_id, policy_name)
    return deny_policy


def delete_deny_policy(iam_client, deny_policy_arn):
  return iam_client.delete_policy(PolicyArn=deny_policy_arn)


def attach_user_policy(iam_client, user_name, policy_arn):
  return iam_client.attach_user_policy(
    UserName=user_name,
    PolicyArn=policy_arn
  )


def attach_role_policy(iam_client, role_name, policy_arn):
  return iam_client.attach_role_policy(
    RoleName=role_name,
    PolicyArn=policy_arn
  )


def detach_user_policy(iam_client, user_name, policy_arn):
  return iam_client.detach_user_policy(
    UserName=user_name,
    PolicyArn=policy_arn
  )


def detach_role_policy(iam_client, role_name, policy_arn):
  return iam_client.detach_role_policy(
    RoleName=role_name,
    PolicyArn=policy_arn
  )

