import time
import helpers


def verify_admin_user(iam_client, user_name):
  admin_logs = [ time.ctime() + ' ' + str(helpers.verify_admin_user(iam_client, user_name)) ]
  return helpers.save_logs(admin_logs, 'ADMIN verify log: ')


def lockdown_nacls(ec2_client):
  nacl_logs = [ time.ctime() + ' Lockdown Network Access Control Lists' ]
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    nacl_logs.append(time.ctime() + ' ' + str(nacl))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.create_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.create_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
  return helpers.save_logs(nacl_logs, 'NACL log: ')


def lockdown_iam(iam_client, account_id, policy_name, users, roles, user_name):
  policy_logs = [ time.ctime() + ' Lockdown IAM Users and Roles' ]
  deny_policy = helpers.create_deny_policy(iam_client, account_id, policy_name)
  for user in users:
    if user['UserName'] != user_name:
      policy_logs.append(time.ctime() + ' ' + str(user))
      try:
        policy_logs.append(time.ctime() + ' ' + str(helpers.attach_user_policy(iam_client, user['UserName'], deny_policy['Arn'])))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(err))
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      policy_logs.append(time.ctime() + ' ' + str(role))
      try:
        policy_logs.append(time.ctime() + ' ' + str(helpers.attach_role_policy(iam_client, role['RoleName'], deny_policy['Arn'])))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(err))
  return helpers.save_logs(policy_logs, 'IAM policy log: ')


def lockdown_s3(s3_client):
  s3_logs = [ time.ctime() + ' Lockdown S3 buckets' ]
  try:
    buckets = helpers.get_buckets(s3_client)
  except Exception as err:
    s3_logs.append(time.ctime() + ' ' + str(err))
  for bucket in [ bucket['Name'] for bucket in buckets ]:
    s3_logs.append(time.ctime() + ' ' + bucket)
    try:
      s3_logs.append(time.ctime() + ' ' + str(s3_client.put_bucket_acl(Bucket=bucket, ACL='private')))
    except Exception as err:
      s3_logs.append(time.ctime() + ' ' + str(err))
  return helpers.save_logs(s3_logs, 'S3 log: ')


def image_instances(ec2_client):
  image_logs = [ time.ctime() + ' Image all instances' ]
  try:
    instances = helpers.get_running_instances(ec2_client)
  except Exception as err:
    image_logs.append(time.ctime() + ' No running instances.')
    return helpers.save_logs(image_logs, 'EC2 image log: ')
  for instance in instances:
    image_logs.append(time.ctime() + ' ' + str(instance))
    try:
      image_logs.append(time.ctime() + ' ' + str(helpers.image_instance(ec2_client, instance['InstanceId'])))
    except Exception as err:
      image_logs.append(time.ctime() + ' ' + str(err))
  return helpers.save_logs(image_logs, 'EC2 image log: ')


def capture_ssm(ec2_client, ssm_client, ssm_command, ssm_document_name, ssm_document_body):
  ssm_logs = [ time.ctime() + ' SSM capture running processes and system memory' ]
  try:
    instances = helpers.get_running_instances(ec2_client)
  except Exception as err:
    ssm_logs.append(time.ctime() + ' No running instances.')
    return helpers.save_logs(ssm_logs, 'SSM log: ')
  try:
    ssm_logs.append(time.ctime() + ' ' + str(helpers.ssm_make_document(ssm_client, ssm_command, ssm_document_name, ssm_document_body)))
  except Exception as err:
    ssm_logs.append(time.ctime() + ' ' + str(err))
  for instance in instances:
    ssm_logs.append(time.ctime() + ' ' + str(instance))
    try:
      ssm_logs.append(time.ctime() + ' ' + helpers.ssm_exec_document(ssm_client, instance['InstanceId'], ssm_document_name))
    except Exception as err:
      ssm_logs.append(time.ctime() + ' ' + str(err))
  return helpers.save_logs(ssm_logs, 'SSM log: ')


def stop_instances(ec2_client):
  instance_logs = [ time.ctime() + ' Stop all instances' ]
  try:
    instances = helpers.get_running_instances(ec2_client)
  except Exception as err:
    instance_logs.append(time.ctime() + ' No running instances.')
    return helpers.save_logs(instance_logs, 'EC2 stop log: ')
  for instance in instances:
    instance_logs.append(time.ctime() + ' ' + str(instance))
    try:
      instance_logs.append(time.ctime() + ' ' + str(helpers.stop_instance(ec2_client, instance['InstanceId'])))
    except Exception as err:
      instance_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(instance_logs, 'EC2 stop log: ')


def lookup_audit_logs(cloudtrail_client, ec2_client):
  audit_logs = [ time.ctime() + ' Lookup Cloudtrail and Flowlogs locations' ]
  audit_logs.extend([ time.ctime() + ' Cloudtrail logs S3 Bucket: ' + trail['S3BucketName'] for trail in cloudtrail_client.describe_trails()['trailList'] ])
  audit_logs.append(time.ctime() + ' ' + str(ec2_client.describe_flow_logs()))
  helpers.save_logs(audit_logs, 'AUDIT log: ')


def unlock_nacls(ec2_client):
  nacl_logs = [ time.ctime() + ' Unlock Network Access Control List' ]
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    nacl_logs.append(time.ctime() + ' ' + str(nacl))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.delete_nacl_entry(ec2_client, True, nacl['NetworkAclId'], 1)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
    try:
      nacl_logs.append(time.ctime() + ' ' + str(helpers.delete_nacl_entry(ec2_client, False, nacl['NetworkAclId'], 2)))
    except Exception as err:
      nacl_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(nacl_logs, 'NACL log: ')


def unlock_iam(iam_client, account_id, policy_name, users, roles):
  policy_logs = [ time.ctime() + ' Unlock IAM Users and Roles' ]
  for user in users:
    policy_logs.append(time.ctime() + ' ' + str(user))
    try:
      policy_logs.append(time.ctime() + ' ' + str(helpers.detach_user_policy(iam_client, user['UserName'], helpers.get_policy_arn(account_id, policy_name))))
    except Exception as err:
      policy_logs.append(time.ctime() + ' ' + str(err))
  for role in roles:
    if helpers.check_aws_roles(role['RoleName']):
      policy_logs.append(time.ctime() + ' ' + str(role))
      try:
        policy_logs.append(time.ctime() + ' ' + str(helpers.detach_role_policy(iam_client, role['RoleName'], helpers.get_policy_arn(account_id, policy_name))))
      except Exception as err:
        policy_logs.append(time.ctime() + ' ' + str(err))
  policy_logs.append(time.ctime() + ' ' + policy_name + ' ' + account_id)
  try:
    policy_logs.append(time.ctime() + ' ' + str(helpers.delete_deny_policy(iam_client, helpers.get_policy_arn(account_id, policy_name))))
  except Exception as err:
    policy_logs.append(time.ctime() + ' ' + str(err))
  helpers.save_logs(policy_logs, 'IAM policy log: ')
