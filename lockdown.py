import argparse
import boto3
import core


parser = argparse.ArgumentParser()
parser.add_argument('--all', action='store_true', help='Locks account, and performs all post lockdown functions')
parser.add_argument('--lock', action='store_true', help='Locks account via NACLs and IAM polices.')
parser.add_argument('--unlock', action='store_true', help='Unlocks account removing NACLs and IAM policies.')
parser.add_argument('--s3', action='store_true', help='Locks S3 with Private ACL on every bucket. CANNOT BE UNDONE.')
parser.add_argument('--nacls', action='store_true', help='Only lock/unlock NACLs.')
parser.add_argument('--iam', action='store_true', help='Only lock/unlock IAM.')
parser.add_argument('--image', action='store_true', help='Image all running instances.')
parser.add_argument('--ssm', action='store_true', help='Attempt to capture running system via SSM.')
parser.add_argument('--stop', action='store_true', help='Stop all running instances.')
parser.add_argument('--logs', action='store_true', help='Report account Cloudtrail and Flowlogs status')
args = parser.parse_args()

iam_client = boto3.client('iam')
ec2_client = boto3.client('ec2')
sts_client = boto3.client('sts')
s3_client = boto3.client('s3')
cloudtrail_client = boto3.client('cloudtrail')

policy_name = 'LockdownDenyAll'
user_name = iam_client.get_user()['User']['UserName']
account_id = sts_client.get_caller_identity()['Account']
users = iam_client.get_account_authorization_details(Filter=['User'])['UserDetailList']
roles = iam_client.get_account_authorization_details(Filter=['Role'])['RoleDetailList']


def lockdown():
  core.lockdown_nacls(ec2_client)
  core.lockdown_iam(iam_client, account_id, policy_name, users, roles, user_name)


def unlock():
  core.unlock_nacls(ec2_client)
  core.unlock_iam(iam_client, account_id, policy_name, users, roles)


def main():
  ### Verify current user has AdministratorAccess policy
  core.verify_admin_user(iam_client, user_name)

  ### Unlock account
  if args.unlock:
    if args.nacls:
      core.unlock_nacls(ec2_client)
    elif args.iam:
      core.unlock_iam(iam_client, account_id, policy_name, users, roles)
    else:
      unlock()

  ### Lock account
  if args.lock:
    if args.nacls:
      core.lockdown_nacls(ec2_client)
    elif args.iam:
      core.lockdown_iam(iam_client, account_id, policy_name, users, roles, user_name)
    else:
      lockdown()

  ### Lock S3
  if args.s3:
    core.lockdown_s3(s3_client)

  ### Snap EBS
  if args.image:
    core.image_instances(ec2_client)

  ### Capture SSM
  if args.ssm:
    core.capture_ssm()

  ### Stop Instances
  if args.stop:
    core.stop_instances(ec2_client)

  ### Lookup Audit Logs
  if args.logs:
    core.lookup_audit_logs(cloudtrail_client, ec2_client)

  ### Lockdown All
  if args.all:
    lockdown()
    core.lockdown_s3(s3_client)
    core.image_instances(ec2_client)
    core.capture_ssm()
    core.stop_instances(ec2_client)
    core.lookup_audit_logs(cloudtrail_client, ec2_client)


if __name__== "__main__":
  main()
