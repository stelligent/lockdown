# AWS Emergency Compromise Response

This tool `lockdown.py` is to be used in the event of aws compromise.  Unfortunately,
frequently we see developers commit aws keys to GitHub, and this typically results in many rogue
instances spun up for cryptomining and other purposes.  Other times, instances themselves may be
compromised. In both cases, account lockdown, while preserving as much data as possible, is the
preferred response.

This program stands apart from other available AWS incident response software, as it leaves the
environment undisturbed.  Changes are solely additive, and can be removed in `unlock` mode.


```
usage: lockdown.py [-h] [--all] [--lock] [--unlock] [--s3] [--nacls] [--iam]
                   [--ebs] [--ssm] [--ec2] [--logs]

optional arguments:
  -h, --help  show this help message and exit
  --all       Locks account, and performs all post lockdown functions
  --lock      Locks account via NACLs and IAM polices.
  --unlock    Unlocks account removing NACLs and IAM policies.
  --s3        Locks S3 with Private ACL on every bucket. CANNOT BE UNDONE.
  --nacls     Only lock/unlock NACLs.
  --iam       Only lock/unlock IAM.
  --ebs       Snapshot all EBS volumes running.
  --ssm       Attempt to capture running system via SSM.
  --ec2       Stop all running instances.
  --logs      Report account Cloudtrail and Flowlogs status
```


AWS profile must be set with "root" keys.  This means the "AdministratorAccess" IAM managed
policy must be attached to the user whose keys are executing this code.


"Unlock" mode will unlock an account after is has been locked down.  Unlock reverts the
applied polices and NACLs that lock down an account.  This should only be executed after
the account has been verified clear of intrusion.


NOTE: This software will render your account unusable by anyone other than you. Please exec with care.


### `python3 lockdown.py` executes the following actions:


1. Cut off all network access to all subnets
   * NACLs are applied to prevent any and all traffic
   * Security groups are left intact for forensics
  

2. Deactivate all IAM users and roles
   * Deny policy is attached to all users, groups and roles.
   * Mitigates attacks such as persistant sts sessions, cross-account access, or cron'd Lambdas.
   * Existing policies are left intact for forensics


3. EBS snapshot all instances
   * All instance volumes are snapshotted for forensics


4. Disable public s3 access
   * Add bucket policy to disable all public reads and writes
   * This protects from data exfiltration and file warehousing


5. Execute any forensic tooling via SSM
   * Capture running processes and system memory


6. Stop all running instances
   * Executes after ebs snapshot and ssm capture
   * Lessens runtime charges


7. Report on cloudtrail and flowlogs status
   * If logs are available, print out location of logs




### `python3 lockdown.py --unlock` executes the following actions:


1. Remove "lockdown" deny all NACLs
   * NACLs previously applied to stop traffic are removed


2. Remove "lockdown" deny all IAM policy
   * Deny all IAM policy is removed from all users and roles
   * Deny all IAM policy is deleted


3. Remove "lockdown" deny all S3 bucket policy
   * Deny all S3 bucket policy is removed from all buckets
