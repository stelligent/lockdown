import time
import helpers


def verify_admin_user(iam_client, user_name):
  admin_logs = [ time.ctime() + ' ' + str(helpers.verify_admin_user(iam_client, user_name)) ]
  return helpers.save_logs(admin_logs, 'ADMIN verify log: ')


def lockdown_nacls(ec2_client):
  nacl_logs = [ 'Lockdown Network Access Control Lists' ]
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(time.ctime() + ' ' + str(nacl) + ' ' + str(helpers.create_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(nacl) + ' ' + str(err))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.create_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
  return helpers.save_logs(nacl_logs, 'NACL log: ')


def lockdown_iam(iam_client, account_id, policy_name, users, roles, user_name):
  policy_logs = [ 'Lockdown IAM Users and Roles' ]
  deny_policy = helpers.create_deny_policy(iam_client, account_id, policy_name)
  for user in users:
    if user['UserName'] != user_name:
      try:
        policy_logs.append(time.ctime() + ' ' + str(user) + ' ' + str(helpers.attach_user_policy(iam_client, user['UserName'], deny_policy['Arn'])))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(user) + ' ' + str(err))
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(time.ctime() + ' ' + str(role) + ' ' + str(helpers.attach_role_policy(iam_client, role['RoleName'], deny_policy['Arn'])))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(role) + ' ' + str(err))
  return helpers.save_logs(policy_logs, 'IAM policy log: ')


def lockdown_s3(s3_client):
  s3_logs = [ 'Lockdown S3 buckets' ]
  try:
    buckets = helpers.get_buckets(s3_client)
  except Exception as err:
    s3_logs.append(time.ctime() + ' ' + str(err))
  for bucket in [ bucket['Name'] for bucket in buckets ]:
    try:
      s3_logs.append(time.ctime() + ' ' + bucket + ' ' + str(s3_client.put_bucket_acl(Bucket=bucket, ACL='private')))
    except Exception as err:
      s3_logs.append(time.ctime() + ' ' + bucket + ' ' + str(err))
  return helpers.save_logs(s3_logs, 'S3 log: ')


def image_instances(ec2_client):
  image_logs = [ 'Image all instances' ]
  try:
    instances = helpers.get_running_instances(ec2_client)
  except Exception as err:
    image_logs.append(time.ctime() + ' ' + str(err))
  for instance in instances:
    try:
      image_logs.append(time.ctime() + ' ' + str(instance) + ' ' + str(helpers.image_instance(ec2_client, instance['InstanceId'])))
    except Exception as err:
      image_logs.append(time.ctime() + ' ' + str(instance) + ' ' + str(err))
  return helpers.save_logs(image_logs, 'EC2 image log: ')


def capture_ssm(ec2_client, ssm_client, ssm_command, ssm_document_name, ssm_document_body):
  ssm_logs = [ 'SSM capture running processes and system memory' ]
  #try:
  instances = helpers.get_running_instances(ec2_client)
  #except Exception as err:
  #  ssm_logs.append(time.ctime() + ' ' + str(err))
  try:
    ssm_logs.append(time.ctime() + ' ' + str(helpers.ssm_make_document(ssm_client, ssm_command, ssm_document_name, ssm_document_body)))
  except Exception as err:
    ssm_logs.append(time.ctime() + ' ' + str(err))
  for instance in instances:
    try:
      ssm_exec = ssm_logs.append(time.ctime() + ' ' + str(instance) + ' ' + helpers.ssm_exec_document(ssm_client, instance['InstanceId'], ssm_document_name))
    except Exception as err:
      ssm_logs.append(time.ctime() + ' ' + str(instance) + str(err))
  return helpers.save_logs(ssm_logs, 'SSM log: ')


def stop_instances(ec2_client):
  instance_logs = [ 'Stop all instances' ]
  try:
    instances = helpers.get_running_instances(ec2_client)
  except Exception as err:
    instance_logs.append(time.ctime() + ' ' + str(err))
  for instance in instances:
    try:
      instance_logs.append(time.ctime() + ' ' + str(instance) + ' ' + str(helpers.stop_instance(ec2_client, instance['InstanceId'])))
    except Exception as err:
      instance_logs.append(time.ctime() + ' ' + str(instance) + ' ' + str(err))
  helpers.save_logs(instance_logs, 'EC2 stop log: ')


def lookup_audit_logs(cloudtrail_client, ec2_client):
  audit_logs = [ 'Lookup Cloudtrail and Flowlogs locations' ]
  audit_logs.extend([ 'Cloudtrail logs S3 Bucket: ' + trail['S3BucketName'] for trail in cloudtrail_client.describe_trails()['trailList'] ])
  audit_logs.append(time.ctime() + ' ' + str(ec2_client.describe_flow_logs()))
  helpers.save_logs(audit_logs, 'AUDIT log: ')


def unlock_nacls(ec2_client):
  nacl_logs = [ 'Unlock Network Access Control List' ]
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    try:
      nacl_logs.append(time.ctime() + ' ' + str(nacl) + ' ' + str(helpers.delete_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(nacl) + ' ' + str(err))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.delete_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(nacl_logs, 'NACL log: ')


def unlock_iam(iam_client, account_id, policy_name, users, roles):
  policy_logs = [ 'Unlock IAM Users and Roles' ]
  for user in users:
    try:
      policy_logs.append(time.ctime() + ' ' + str(user) + ' ' + str(helpers.detach_user_policy(iam_client, user['UserName'], helpers.get_policy_arn(account_id, policy_name))))
    except Exception as err:
      policy_logs.append(time.ctime() + ' ' + str(user) + ' ' + str(err))
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      try:
        policy_logs.append(time.ctime() + ' ' + str(role) + ' ' + str(helpers.detach_role_policy(iam_client, role['RoleName'], helpers.get_policy_arn(account_id, policy_name))))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(role) + ' ' + str(err))
  try:
    policy_logs.append(time.ctime() + ' ' + policy_name + ' ' + account_id + ' ' + str(helpers.delete_deny_policy(iam_client, helpers.get_policy_arn(account_id, policy_name))))
  except Exception as err:
    policy_logs.append(time.ctime() + ' ' + policy_name + ' ' + account_id + str(err))
  helpers.save_logs(policy_logs, 'IAM policy log: ')
