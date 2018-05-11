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
  admin_logs = [ time.ctime() + ' ' + str(helpers.verify_admin_user(iam_client, user_name)) ]
  helpers.save_logs(admin_logs, 'ADMIN verify log: ')


def lockdown_nacls(ec2_client):
  nacl_logs.append('Lockdown Network Access Control Lists')
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.create_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.create_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(nacl_logs, 'NACL log: ')


def lockdown_iam(iam_client, account_id, policy_name):
  policy_logs.append('Lockdown IAM Users and Roles')
  deny_policy = helpers.create_deny_policy(iam_client, account_id, policy_name)
  for user in users:
    if user['UserName'] != user_name:
      try:
        policy_logs.append(time.ctime() + ' ' + str(helpers.attach_user_policy(iam_client, user['UserName'], deny_policy['Arn'])))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(err))
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(time.ctime() + ' ' + str(helpers.attach_role_policy(iam_client, role['RoleName'], deny_policy['Arn'])))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(policy_logs, 'IAM policy log: ')


def lockdown_s3():
  s3_logs = [ 'Lockdown S3 buckets' ]
  helpers.save_logs(s3_logs, 'S3 log: ')


def snapshot_ebs():
  ebs_logs = [ 'Snapshot all instances and mounted volumes' ]
  helpers.save_logs(ebs_logs, 'EBS log: ')


def capture_ssm():
  ssm_logs = [ 'SSM capture running processes and system memory, if available' ]
  helpers.save_logs(ssm_logs, 'SSM log: ')


def stop_instances():
  ec2_logs = [ 'Stop all instances' ]
  helpers.save_logs(ec2_logs, 'EC2 log: ')


def lookup_audit_logs():
  audit_logs = [ 'Lookup Cloudtrail and Flowlogs locations, if available' ]
  helpers.save_logs(audit_logs, 'AUDIT log: ')


def unlock_nacls(ec2_client):
  nacl_logs = [ 'Unlock Network Access Control List' ]
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.delete_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.delete_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(nacl_logs, 'NACL log: ')


def unlock_iam(iam_client, account_id, policy_name):
  policy_logs = [ 'Unlock IAM Users and Roles' ]
  for user in users:
    try:
      policy_logs.append(time.ctime() + ' ' + str(helpers.detach_user_policy(iam_client, user['UserName'], helpers.get_policy_arn(account_id, policy_name))))
    except Exception as err:
      policy_logs.append(time.ctime() + ' ' + str(err))
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(time.ctime() + ' ' + str(helpers.detach_role_policy(iam_client, role['RoleName'], helpers.get_policy_arn(account_id, policy_name))))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(err))
  try:
    policy_logs.append(time.ctime() + ' ' + str(helpers.delete_deny_policy(iam_client, helpers.get_policy_arn(account_id, policy_name))))
  except Exception as err:
    policy_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(policy_logs, 'IAM policy log: ')


def unlock_s3():
  s3_logs = [ 'Unlock S3' ]
  helpers.save_logs(s3_logs, 'S3 log: ')


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
  else:
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
    else:
      lockdown(ec2_client, iam_client, account_id, policy_name)


if __name__== "__main__":
  main()
