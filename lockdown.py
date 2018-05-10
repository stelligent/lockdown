import sys
import boto3
import helpers

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


### Verify current user has AdministratorAccess IAM managed policy attached.
helpers.verify_admin_user(iam_client, user_name)


### If no arguments to script are given, execute default lockdown behaviour.
if (len(sys.argv) == 1):

  print("\n\n1. Network Access Control List Deny:")
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


  print("3.  - all instances and mount volumes are snapshotted.")


  print("4.  - add bucket policy jinja template to disable all public reads and writes.")


  print("5.  - attempt to capture running processes and system memory via SSM, if available.")


  print("6.  - stop all instances.")


  print("7.  - lookup and print cloudtrail logs and vpc flowlogs location, if available.")



### If single argument "revert" is given, unlock account
elif (sys.argv[1] == "revert"):

  print("1. Network Access Control List Allow.")
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


  print("2. Unlock IAM Users, Groups, and Roles")
  for user in users:
    try:
      policy_logs.append(helpers.detach_user_policy(iam_client, user['UserName'], helpers.get_policy_arn(account_id, policy_name)))
    except Exception as err:
      print(err)
  for role in roles:
    if role['RoleName'] != 'AWSServiceRoleForOrganizations':
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




