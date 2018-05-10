import sys
import boto3
import helpers
import argparse

iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
sts_client = boto3.client('sts')

parser = argparse.ArgumentParser()
parser.add_argument('--unlock', action='store_true', help='Unlocks IAM users/roles, NACLs, and S3 buckets')
args = parser.parse_args()

nacl_logs = []
policy_logs = []
policy_name = 'LockdownDenyAll'
user_name = iam_client.get_user()['User']['UserName']
account_id = sts_client.get_caller_identity()['Account']
users = iam_client.get_account_authorization_details(Filter=['User'])['UserDetailList']
roles = iam_client.get_account_authorization_details(Filter=['Role'])['RoleDetailList']


### Verify current user has AdministratorAccess IAM managed policy attached.
helpers.verify_admin_user(iam_client, user_name)


### If no arguments to script are given, execute default lockdown behaviour.
if not args.unlock:

  print("\n\n1. Lockdown Network Access Control Lists:")
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    nacl_logs.append(helpers.create_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1))
    nacl_logs.append(helpers.create_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2))
  helpers.save_logs(nacl_logs, "NACL log: ")


  print("\n\n2. Lockdown IAM Users and Roles")
  deny_policy = helpers.create_deny_policy(iam_client, account_id, policy_name)
  for user in users:
    if user['UserName'] != user_name:
      try:
        policy_logs.append(helpers.attach_user_policy(iam_client, user['UserName'], deny_policy['Arn']))
      except Exception as err:
        print(err)
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(helpers.attach_role_policy(iam_client, role['RoleName'], deny_policy['Arn']))
      except Exception as err:
        print(err)
  helpers.save_logs(policy_logs, "IAM policy log: ")


  print("\n\n3. Lockdown S3 buckets.")


  print("\n\n4. Snapshot all instances and mounted volumes.")


  print("\n\n5. SSM capture running processes and system memory, if available.")


  print("\n\n6. Stop all instances.")


  print("\n\n7. Lookup Cloudtrail and Flowlogs locations, if available.")


### Unlock account
if args.unlock:

  print("1. Unlock Network Access Control List.")
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(helpers.delete_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1))
    except Exception as err:
      print(err)
    try:
      nacl_logs.append(helpers.delete_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2))
    except Exception as err:
      print(err)
  helpers.save_logs(nacl_logs, "NACL log: ")


  print("2. Unlock IAM Users and Roles")
  for user in users:
    try:
      policy_logs.append(helpers.detach_user_policy(iam_client, user['UserName'], helpers.get_policy_arn(account_id, policy_name)))
    except Exception as err:
      print(err)
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(helpers.detach_role_policy(iam_client, role['RoleName'], helpers.get_policy_arn(account_id, policy_name)))
      except Exception as err:
        print(err)
  helpers.save_logs(policy_logs, "IAM policy log: ")
  try:
    delete_policy = helpers.delete_deny_policy(iam_client, helpers.get_policy_arn(account_id, policy_name))
  except Exception as err:
    print(err)


  print("3. Unlock S3.")
  print("  - Remove deny public access policy applied to s3 buckets is removes")




