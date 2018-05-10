import sys

def check_aws_roles(role_name):
  if (
    role_name != 'AWSServiceRoleForOrganizations' and
    role_name != 'AWSServiceRoleForAutoScaling'
  ):
    return True
  else:
    return False

def verify_admin_user(iam_client, user_name):
  print("Verify current user has Administrator privileges.")
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
    print("Current aws profile user keys are valid.  continuing.")
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
    deny_policy['Arn'] = get_policy_arn(account_id)
    return deny_policy


def delete_deny_policy(iam_client, deny_policy_arn):
  delete_policy = iam_client.delete_policy(PolicyArn=deny_policy_arn)
  print("Delete policy: " + str(delete_policy))
  return delete_policy


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

