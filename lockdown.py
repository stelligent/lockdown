import argparse
import boto3
import core


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

policy_name = 'LockdownDenyAll'
user_name = iam_client.get_user()['User']['UserName']
account_id = sts_client.get_caller_identity()['Account']
users = iam_client.get_account_authorization_details(Filter=['User'])['UserDetailList']
roles = iam_client.get_account_authorization_details(Filter=['Role'])['RoleDetailList']


def lockdown():
  core.lockdown_nacls(ec2_client)
  core.lockdown_iam(iam_client, account_id, policy_name, users, roles, user_name)
  core.lockdown_s3()
  core.snapshot_ebs()
  core.capture_ssm()
  core.stop_instances()
  core.lookup_audit_logs()


def unlock():
  core.unlock_nacls(ec2_client)
  core.unlock_iam(iam_client, account_id, policy_name, users, roles)
  core.unlock_s3()


def main():
  ### Verify current user has AdministratorAccess policy
  core.verify_admin_user(iam_client, user_name)

  ### Unlock account
  if args.unlock:
    if args.nacls:
      core.unlock_nacls()
    elif args.iam:
      core.unlock_iam()
    elif args.s3:
      core.unlock_s3()
    else:
      unlock()

  ### Lock account
  else:
    if args.nacls:
      core.lockdown_nacls()
    elif args.iam:
      core.lockdown_iam()
    elif args.s3:
      core.lockdown_s3()
    elif args.ebs:
      core.snapshot_ebs()
    elif args.ssm:
      core.capture_ssm()
    elif args.ec2:
      core.stop_instances()
    elif args.logs:
      core.lookup_audit_logs()
    else:
      lockdown()


if __name__== "__main__":
  main()
