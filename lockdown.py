import sys
import boto3
import jinja2



print("Verify current user has Administrator privileges.")
iam_client = boto3.client('iam')
user_name = iam_client.get_user()['User']['UserName']
user_policies = iam_client.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
for policy in user_policies:
  if policy['PolicyName'] == "AdministratorAccess":
    user_admin = True
if user_admin:
  print("current aws profile user keys are valid.  continuing.")
else:
  print("In order to run this code, please add the AdministratorAccess managed IAM policy to your current user.")
  sys.exit(1)




if (len(sys.argv) == 1):

  print("Network Access Control List Deny.")
  ec2_client = boto3.client('ec2')
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    ec2_client.create_network_acl_entry(
      CidrBlock='0.0.0.0/0',
      Egress=True,
      Protocol='-1',
      RuleAction='deny',
      RuleNumber=1,
      NetworkAclId=nacl['NetworkAclId']
    )
    ec2_client.create_network_acl_entry(
      CidrBlock='0.0.0.0/0',
      Egress=False,
      Protocol='-1',
      RuleAction='deny',
      RuleNumber=2,
      NetworkAclId=nacl['NetworkAclId']
    )


  print("  - deny policy jinja template is attached to all users, groups and roles.")
  print("    -  exempt this user: " + user_name + " from deny policy addition")

  print("  - all instances and mount volumes are snapshotted.")

  print("  - add bucket policy jinja template to disable all public reads and writes.")

  print("  - attempt to capture running processes and system memory via SSM, if available.")

  print("  - stop all instances.")
  
  print("  - lookup and print cloudtrail logs and vpc flowlogs location, if available.")


elif (sys.argv[1] == "revert"):
  print("Network Access Control List Allow.")
  ec2_client = boto3.client('ec2')
  nacls = ec2_client.describe_network_acls()['NetworkAcls']
  for nacl in nacls:
    ec2_client.delete_network_acl_entry(
      Egress=True,
      RuleNumber=1,
      NetworkAclId=nacl['NetworkAclId']
    )
    ec2_client.delete_network_acl_entry(
      Egress=False,
      RuleNumber=2,
      NetworkAclId=nacl['NetworkAclId']
    )


  print("  - remove network deny ACLs, if existing")

  print("  - Deny policy applied to users, groups, and roles is removed -- tags on policies not yet supported?")

  print("  - Remove deny public access policy applied to s3 buckets is removes")
