import sys
import boto3
import helpers
import argparse
import time


parser = argparse.ArgumentParser()
parser.add_argument('--unlock', action='store_true', help='Unlocks IAM users/roles, NACLs, and S3 buckets')
parser.add_argument('--nacls', action='store_true', help='Only lock/unlock NACLs')
parser.add_argument('--iam', action='store_true', help='Only lock/unlock IAM')
parser.add_argument('--s3', action='store_true', help='Only lock/unlock S3')
parser.add_argument('--ebs', action='store_true', help='Only snapshot EBS')
parser.add_argument('--ssm', action='store_true', help='Only capture_ssm')
parser.add_argument('--ec2', action='store_true', help='Only stop instances')
parser.add_argument('--logs', action='store_true', help='Only report Cloudtrail and Flowlogs status')
args = parser.parse_args()

iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
sts_client = boto3.client('sts')

nacl_logs = []
policy_logs = []
policy_name = 'LockdownDenyAll'
user_name = iam_client.get_user()['User']['UserName']
account_id = sts_client.get_caller_identity()['Account']
users = iam_client.get_account_authorization_details(Filter=['User'])['UserDetailList']
roles = iam_client.get_account_authorization_details(Filter=['Role'])['RoleDetailList']


def verify_admin_user(iam_client, user_name):
  helpers.save_logs(time.ctime() + str(helpers.verify_admin_user(iam_client, user_name)), "Verify admin: ")


def lockdown_nacls(ec2_client):
  print("\n\n1. Lockdown Network Access Control Lists:")
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(time.ctime() + " " + helpers.create_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1))
    except Exception as err:
      nacl_logs.append(time.ctime() + " " + err)
    try:
      nacl_logs.append(time.ctime() + " " + helpers.create_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2))
    except Exception as err:
      nacl_logs.append(time.ctime() + " " + err)
  helpers.save_logs(nacl_logs, "NACL log: ")


def lockdown_iam(iam_client, account_id, policy_name):
  print("\n\n2. Lockdown IAM Users and Roles")
  deny_policy = helpers.create_deny_policy(iam_client, account_id, policy_name)
  for user in users:
    if user['UserName'] != user_name:
      try:
        policy_logs.append(time.ctime() + " " + helpers.attach_user_policy(iam_client, user['UserName'], deny_policy['Arn']))
      except Exception as err:
        policy_logs.append(time.ctime() + " " + err)
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(time.ctime() + " " + helpers.attach_role_policy(iam_client, role['RoleName'], deny_policy['Arn']))
      except Exception as err:
        policy_logs.append(time.ctime() + " " + err)
  helpers.save_logs(policy_logs, "IAM policy log: ")


def lockdown_s3():
  print("\n\n3. Lockdown S3 buckets.")


def snapshot_ebs():
  print("\n\n4. Snapshot all instances and mounted volumes.")


def capture_ssm():
  print("\n\n5. SSM capture running processes and system memory, if available.")


def stop_instances():
  print("\n\n6. Stop all instances.")


def lookup_audit_logs():
  print("\n\n7. Lookup Cloudtrail and Flowlogs locations, if available.")


def unlock_nacls(ec2_client):
  print("1. Unlock Network Access Control List.")
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(time.ctime() + " " + helpers.delete_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1))
    except Exception as err:
      nacl_logs.append(time.ctime() + " " + err)
    try:
      nacl_logs.append(time.ctime() + " " + helpers.delete_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2))
    except Exception as err:
      nacl_logs.append(time.ctime() + " " + err)
  helpers.save_logs(nacl_logs, "NACL log: ")


def unlock_iam(iam_client, account_id, policy_name):
  print("2. Unlock IAM Users and Roles")
  for user in users:
    try:
      policy_logs.append(time.ctime() + " " + helpers.detach_user_policy(iam_client, user['UserName'], helpers.get_policy_arn(account_id, policy_name)))
    except Exception as err:
      policy_logs.append(time.ctime() + " " + err)
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(time.ctime() + " " + helpers.detach_role_policy(iam_client, role['RoleName'], helpers.get_policy_arn(account_id, policy_name)))
      except Exception as err:
        policy_logs.append(time.ctime() + " " + err)
  helpers.save_logs(policy_logs, "IAM policy log: ")
  try:
    helpers.save_logs(time.ctime() + " " + str(helpers.delete_deny_policy(iam_client, helpers.get_policy_arn(account_id, policy_name))), "Delete policy: ")
  except Exception as err:
    helpers.save_logs(time.ctime() + " " + err, "Delete policy: ")


def unlock_s3():
  print("3. Unlock S3.")
  print("  - Remove deny public access policy applied to s3 buckets is removes")


def lockdown(ec2_client, iam_client, account_id, policy_name):
  lockdown_nacls(ec2_client)
  lockdown_iam(iam_client, account_id, policy_name)
  lockdown_s3()
  snapshot_ebs()
  capture_ssm()
  stop_instances()
  lookup_audit_logs()


def unlock(ec2_client, iam_client, account_id, policy_name):
  unlock_nacls(ec2_client)
  unlock_iam(iam_client, account_id, policy_name)
  unlock_s3()


def main():
  ### Verify current user has AdministratorAccess policy
  verify_admin_user(iam_client, user_name)

  ### Unlock account
  if args.unlock:
    if args.nacls:
      unlock_nacls(ec2_client)
    elif args.iam:
      unlock_iam(iam_client, account_id, policy_name)
    elif args.s3:
      unlock_s3()
    else:
      unlock(ec2_client, iam_client, account_id, policy_name)

  ### Lock account
  else
    if args.nacls:
      lockdown_nacls(ec2_client)
    elif args.iam:
      lockdown_iam(iam_client, account_id, policy_name)
    elif args.s3:
      lockdown_s3()
    elif args.ebs:
      snapshot_ebs()
    elif args.ssm:
      capture_ssm()
    elif args.ec2:
      stop_instances()
    elif args.logs:
      lookup_audit_logs()
    else
      lockdown(ec2_client, iam_client, account_id, policy_name))


if __name__== "__main__":
  main()
