# Running the CloudWatch Logs sizing tool

These steps take about 15 minutes. The tool is read-only: it reads log group names and CloudWatch metrics and never reads log contents. A full scan of a large organization typically costs well under $1 in CloudWatch API charges, and the tool prints an estimate before it requests any metrics.

When you are done, send `log_sizing_results.zip` to your Coralogix contact. Add `--redact` (step 4) if log group names must not leave your organization.

## 1. Install

You need Python 3.9 or newer. The `python3` that ships with macOS is fine. You also need the AWS CLI credentials you normally use.

```bash
python3 -m pip install -r requirements.txt
```

## 2. Pick how to reach your accounts

**One account, or a few accounts you already have CLI or SSO profiles for:** skip to step 3.

**Many accounts, or a whole AWS Organization:** deploy the read-only role `CoralogixLogSizingRole` to every account in scope.

a. In the CloudFormation console of the **management account**, create a StackSet from `iam_log_sizing_role.yaml`:

- Permissions: *Service-managed permissions*
- Parameter `TrustedAccountId`: the account you will run the tool from, usually the management account
- Deployment targets: your organization or the OUs in scope
- Regions: one region only (IAM is global), for example `us-east-1`
- Capabilities: tick *IAM resources with custom names*

b. Service-managed StackSets skip the management account itself. If you also want it scanned, either deploy the same template there as a normal stack, or do nothing: when the role is missing, the tool uses your own credentials in the account it runs from.

c. Optionally, set `TrustedPrincipalArn` so that only one principal can assume the role. For example, your SSO admin role: `arn:aws:iam::<TrustedAccountId>:role/aws-reserved/sso.amazonaws.com/*/AWSReservedSSO_AdministratorAccess_*`.

Then create the account list:

```bash
python3 discover_accounts.py
```

This writes `accounts.json`. If you skip it, the tool can list Organization accounts itself when you run it from the management or a delegated-admin account.

## 3. Preflight check

Preflight runs each required call once and prints a pass/fail table. Use the same account options you will use in step 4.

```bash
python3 collect_log_sizing.py --preflight
```

```bash
python3 collect_log_sizing.py --profiles prod staging --preflight
```

```bash
python3 collect_log_sizing.py --role-name CoralogixLogSizingRole --accounts-file accounts.json --preflight
```

If preflight fails:

| Message | Fix |
| --- | --- |
| `SSO session expired or missing; run: aws sso login --profile X` | Run that command, then retry |
| `sts:AssumeRole ... FAIL` | Check that the StackSet reached those accounts and that `TrustedAccountId` is the account you run from |
| `logs:DescribeLogGroups FAIL access_denied` | The role or user is missing the permissions in `iam_log_sizing_role.yaml` |
| `blocked by a service control policy` | An SCP denies the region. This is expected for regions your organization blocks; those regions are reported as `scp_denied` and do not fail the run. |

## 4. Run the scan

Use the same account options as in step 3:

```bash
python3 collect_log_sizing.py --role-name CoralogixLogSizingRole --accounts-file accounts.json --check-subscriptions
```

Useful additions:

- `--redact` hashes log group names, keeping known prefixes such as `/aws/lambda/`.
- `--regions us-east-1 eu-west-1` limits the scan to those regions.
- `--output results/acme` writes the files to another location and prefix.
- `--yes` skips the confirmation prompt. The prompt appears only when the estimated cost is above $5 and you are running in a terminal.

The scan runs in three phases (authenticate, list log groups, read metrics) and prints a summary at the end. You can stop it safely with Ctrl+C; whatever was measured is still written.

## 5. Check the result and send the files

The run writes four report files and a zip that contains all of them:

- `log_sizing_summary.txt`: the human-readable report
- `log_sizing_summary.json`: the same report as JSON
- `log_sizing_regions.csv`: one row per account and region, with its status
- `log_sizing_log_groups.csv`: one row per log group
- `log_sizing_results.zip`: the four files above in one archive

Before sending them, look at the **NOT FULLY SCANNED** section of the summary and check the exit code:

- `0`: everything in scope was measured.
- `2`: some accounts or regions failed; the reasons are listed. Fix them and run again, or send the files anyway and point out what was missing.
- `1`: nothing could be scanned. Run `--preflight` again.

Send `log_sizing_results.zip` to your Coralogix contact. You don't need to send the other files separately.

## FAQ

**Does this read my logs?** No. It reads log group metadata and the `IncomingBytes` and `IncomingLogEvents` metrics only.

**What does it cost?** About $0.01 per 1,000 metrics, and each log group needs 2 metrics, so 50,000 log groups cost about $1. The estimate is printed before any metrics are requested.

**Why is the account-level total higher than the sum of the log groups?** Log groups deleted during the window still count in the account-level metric. That difference appears as *Deleted log groups GB/day*.

**Some logs are missing, like ELB access logs or VPC Flow Logs to S3.** The tool measures CloudWatch Logs only. Logs that services write directly to S3 or Firehose need separate sizing.
