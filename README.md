# AWS Emergency Compromise Response

This tool `lockdown.py` is to be used in the event of aws compromise.  Unfortunately,
frequently we see developers commit aws keys to GitHub, and this typically results in many rogue
instances spun up for cryptomining and other purposes.  Other times, instances themselves may be
compromised. In both cases, account lockdown, while preserving as much data as possible, is the
preferred response.

This program stands apart from other available AWS incident response software, as it leaves the
environment undisturbed.  Changes are solely additive, and can be removed in `unlock` mode.


```
usage: lockdown.py [-h] [--unlock] [--nacls] [--iam] [--s3] [--ebs] [--ssm]
                   [--ec2] [--logs]

optional arguments:
  -h, --help  show this help message and exit
  --unlock    Unlocks IAM users/roles, NACLs, and S3 buckets
  --nacls     Only lock/unlock NACLs
  --iam       Only lock/unlock IAM
  --s3        Only lock/unlock S3
  --ebs       Only snapshot EBS
  --ssm       Only capture_ssm
  --ec2       Only stop instances
  --logs      Only report Cloudtrail and Flowlogs status
```


AWS profile must be set with "root" keys.  This means the "AdministratorAccess" aws managed
policy must be attached to the user whose keys are executing this code.


"Unlock" mode will unlock an account after is has been locked down.  Unlock reverts the
applied polices and NACLs that lock down an account.  This should only be executed after
the account has been verified clear of intrusion.


### `python3 lockdown.py` will take the following actions upon execution:


- 1. cut off all network access to all subnets
  - acls are applied to prevent any and all traffic
  - security groups are left intact for forensics
  

- 2. deactivate all iam users and roles
  - deny policy is attached to all users, groups and roles.
    -  this mitigates attacks such as persistant sts sessions, cross-account access,
       or as part of a future event, such as a cron'd lambda or scheduled datapipeline event.
  - existing policies are left intact for forensics


- 3. ebs snapshot all instances
  - all instance volumes are snapshotted for forensics


- 4. disable public s3 access
  - add bucket policy to disable all public reads and writes
    - this protects from data exfiltration and file warehousing


- 5. execute any forensic tooling via SSM
  - attempt to capture running processes and system memory


- 6. stop all running instances
  - stops instances after snapshotting, and possible ssm action, so as to lessen runtime charges


- 7. report on cloudtrail and flowlogs status
  - if logs are available, print out location of logs




### `python3 lockdown.py --unlock` will take the following actions upon execution:


- 1. remove "lockdown" applied deny ACLs, if existing
  - ACLs applied to stop traffic are removed


- 2. detach deny policy from all users, groups, and roles
  - Deny policy applied to prevent API calls is removed


- 3. remove s3 bucket deny policy
  - Remove deny public access policy applied during lockdown from s3 buckets
