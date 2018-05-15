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
                   [--image] [--ssm] [--stop] [--logs]

optional arguments:
  -h, --help  show this help message and exit
  --all       Locks account, and performs all post lockdown functions
  --lock      Locks account via NACLs and IAM polices.
  --unlock    Unlocks account removing NACLs and IAM policies.
  --s3        Locks S3 with Private ACL on every bucket. CANNOT BE UNDONE.
  --nacls     Only lock/unlock NACLs.
  --iam       Only lock/unlock IAM.
  --image     Image all running instances.
  --ssm       Attempt to capture running system via SSM.
  --stop      Stop all running instances.
  --logs      Report account Cloudtrail and Flowlogs status
```


AWS profile must be set with "root" keys.  This means the "AdministratorAccess" IAM managed
policy must be attached to the user whose keys are executing this code.


"Unlock" mode will unlock an account after is has been locked down.  Unlock reverts the
applied IAM polices and NACLs that lock down an account.  This should only be executed after
the account has been verified clear of intrusion.


### `python3 lockdown.py --lock`


1. Cut off all network access to all subnets.
   * NACLs are applied to prevent any and all traffic.
   * Security groups are left intact for forensics.
  

2. Deactivate all IAM users and roles.
   * Deny policy is attached to all users, groups and roles.
   * Mitigates attacks such as persistant sts sessions, cross-account access, or cron'd Lambdas.
   * Existing policies are left intact for forensics.


### `python3 lockdown.py --unlock`


1. Remove "lockdown" deny all NACLs.
   * NACLs previously applied to stop traffic are removed.


2. Remove "lockdown" deny all IAM policy.
   * Deny all IAM policy is removed from all users and roles.
   * Deny all IAM policy is deleted.


### `python lockdown --all`

1. Lock all the things.
   * NACLs.
   * IAM Policies.


2. Image all instances.
   * All running instances are imaged.


3. Disable public S3 access on all buckets.
   * Add Private ACL to all buckets to disable all public reads and writes.
   * This protects from data exfiltration and file warehousing.
   * This is irreversible and must be restored manually, if necessary.


4. Execute any forensic tooling via SSM.
   * Capture running processes and system memory.


5. Stop all running instances.
   * Executes after ebs snapshot and ssm capture.
   * Minimizes runtime charges.


6. Report on Cloudtrail and Flowlogs status.
   * If logs are available, print out location of logs.


#### NOTE: This software will render your account unusable by anyone other than you. Please exec with care.
