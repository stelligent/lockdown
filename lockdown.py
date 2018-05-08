import boto3

# check to make sure root account

1. cut off all network access to all subnets
  - security group rules are zeroed out
  - acls are applied to prevent any and all traffic

2. deactivates all iam users and deletes roles
  - deactivates all iam user accounts
  - deletes all iam roles, which could be used for cross-account access, or as part of a future event,
      such as a cron'd lambda or scheduled datapipeline

3. ebs snapshot all instances
  - all instance volumes are snapshotted for any future forensics

4. execute any forensic tooling via SSM
  - attempt to capture running processes and system memory

5. report on cloudtrail and flowlogs status
  - if logs are available, print out location of logs
