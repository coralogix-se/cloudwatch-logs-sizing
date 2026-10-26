# CloudWatch Logs ingestion sizing for Coralogix

`collect_log_sizing.py` measures how much log data your AWS accounts send to Amazon CloudWatch Logs, so that Coralogix can size the plan for shipping those logs. It covers every log group in every enabled region of every account in scope.

For each log group, and rolled up by region, account and organization, it reports:

| Measure | Source | Notes |
| --- | --- | --- |
| Ingested bytes | `AWS/Logs` `IncomingBytes` | Uncompressed size of log events at ingestion |
| Log events | `AWS/Logs` `IncomingLogEvents` | Number of events |

Both are read as daily sums over the last `--lookback-days` complete UTC days (default 30). From these the tool reports the daily average, the peak day, the p95 day and the total for the window. Monthly volume is 30 × the daily average. **GB means decimal GB (10⁹ bytes).**

For step-by-step setup and run instructions, see [INSTRUCTIONS.md](INSTRUCTIONS.md).

## What the tool guarantees

- **Read-only, no log contents.** The only API calls are `logs:DescribeLogGroups`, `cloudwatch:GetMetricData`, `ec2:DescribeRegions` and identity lookups. Two calls are optional: `iam:ListAccountAliases` and `logs:DescribeSubscriptionFilters`, the second only with `--check-subscriptions`. The tool never calls `GetLogEvents`, `FilterLogEvents` or Logs Insights.
- **No silent zeros.** Every account and region gets a status: `ok`, `access_denied`, `scp_denied`, `throttled`, `partial`, `region_disabled`, `error` or `not_run`. A region that could not be measured is listed under *NOT FULLY SCANNED* and left out of the totals; it is never counted as 0.
- **No double counting.** Log groups shared through CloudWatch cross-account observability are counted only in the account that owns them, because `includeLinkedAccounts` is never set.

## Quick start

```bash
python3 -m pip install -r requirements.txt
```

```bash
python3 collect_log_sizing.py --preflight
```

```bash
python3 collect_log_sizing.py
```

With no account options, the tool scans the account behind your current AWS credentials, in every enabled region. For several accounts, see [Choosing accounts](#choosing-accounts).

**Requirements:** Python 3.9 or newer (the `/usr/bin/python3` that ships with macOS works) and boto3 1.34 or newer. `tqdm` is optional; if it is installed, the tool shows progress bars.

> boto3 prints a `PythonDeprecationWarning` on Python 3.9. It is harmless. To hide it, use Python 3.10+ or run with `python3 -W ignore collect_log_sizing.py ...`.

## Choosing accounts

| Mode | Command | When to use |
| --- | --- | --- |
| Current credentials | `python3 collect_log_sizing.py` | One account |
| CLI profiles | `--profiles prod staging dev` | A few accounts you already have profiles or SSO for |
| Cross-account role, file | `--role-name CoralogixLogSizingRole --accounts-file accounts.json` | Many accounts, with the role deployed to each |
| Cross-account role, Organizations | `--role-name CoralogixLogSizingRole` | Run from the management or delegated-admin account to scan every active account |

`accounts.json` is a list such as `[{"id": "123456789012", "name": "prod"}]`. Put account IDs in quotes so leading zeros are kept. To create the file, run `discover_accounts.py`, which tries Organizations, then the SSO cache, then your CLI profiles. You can also run `export_accounts.sh`, which uses Organizations only. Without `--role-name`, each entry needs a `"profile"` key.

**Management account.** Service-managed StackSets do not deploy to the management account. If the role cannot be assumed in the account the tool is running in, the tool uses the caller's own credentials there instead. The regions CSV records this as `auth=caller_credentials`. Any other account where the role cannot be assumed is reported as skipped.

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| `--regions R [R ...]` | all enabled | Scan only these regions. Requested regions that are not enabled are reported as `region_disabled`. |
| `--lookback-days N` | 30 | Complete UTC days to measure, from 1 to 455 (the retention for daily-period metrics). |
| `--workers N` | 10 | Account-region pairs scanned in parallel, from 1 to 50. |
| `--output PREFIX` | `log_sizing` | Output file prefix. It can include a directory. |
| `--check-subscriptions` | off | Also counts the existing subscription filters on active Standard-class log groups. This makes one API call per log group. |
| `--redact` | off | Replaces log group names with stable SHA-256 hashes (first 12 characters) and keeps known prefixes such as `/aws/lambda/`. Also hashes the caller's principal name and reduces subscription destinations to their type. |
| `--preflight` | off | Runs each required call once in one account and region, prints a pass/fail table, then exits. In role mode it also tries `AssumeRole` into every account. |
| `--yes` | off | Skips the confirmation prompt. |

## How it collects

For each account and enabled region:

1. **Inventory.** The tool pages through `DescribeLogGroups` (up to 50 per page) and records each log group's name and `logGroupClass`. It uses the full inventory rather than `ListMetrics`, because `ListMetrics` only returns metrics active in the last 2 weeks.
2. **Window.** `end` is today at 00:00 UTC and `start` is `end − lookback_days`, so only complete UTC days are counted.
3. **Per-log-group metrics.** `GetMetricData` runs with `Period=86400` and `Stat=Sum`, with two queries per log group, up to 500 queries per call. Every `NextToken` page is followed, and results are merged by query ID and UTC day. `PartialData` and `InternalError` results are retried; if they persist, the result is flagged `partial`. `Forbidden` is recorded as `access_denied`. A day with no datapoint counts as 0 for that day.
4. **Account-level check.** The same two metrics are also read with no dimensions, which gives the region total. This total is the headline figure, because it includes log groups deleted during the window. The per-log-group data is used for the breakdowns. If the two differ by more than 5%, the difference is flagged, and it usually means log groups were deleted.

The account-level query also runs in regions with no log groups, because log groups deleted during the window may still have ingestion there.

### Robustness

- Every client uses adaptive retries (`max_attempts=10`) and an explicit region, and the throttle retry count is reported.
- Each account has one set of role credentials that re-assumes the role before the 1-hour session expires. Every task builds its own boto3 session from those credentials.
- `AssumeRole` goes to a regional STS endpoint, so its tokens also work in opt-in regions. The partition (`aws`, `aws-us-gov`, `aws-cn`) is taken from the caller's ARN.
- Timestamps are converted to UTC before daily totals are built, so results are the same in any local time zone.
- An `AccessDenied` caused by a service control policy is recorded as `scp_denied`. It is reported but does not count as a failure, because many organizations block unused regions on purpose.
- An expired SSO session gives the message `run: aws sso login --profile X` rather than a stack trace.

### Log group classes

| Class | Shippable with subscription filters | Why |
| --- | --- | --- |
| `STANDARD` | Yes | Supports subscription filters |
| `INFREQUENT_ACCESS` | No | This class does not support subscription filters |
| `DELIVERY` | No | Only delivers Lambda logs to S3 or Firehose (2-day fixed retention); ship from that destination instead |

These rules come from [AWS: Log classes](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html).

## Outputs

| File | Contents |
| --- | --- |
| `<prefix>_log_groups.csv` | One row per log group: account, region, name, category, class, shippable, subscription filters (with `--check-subscriptions`), totals, average and peak GB/day and events/day, average event size, status |
| `<prefix>_regions.csv` | One row per account and region: auth method, status and error, log group count, account-level total, sum of log groups, gap %, average GB/day and events/day |
| `<prefix>_summary.txt` | Human-readable report (also printed at the end of the run) |
| `<prefix>_summary.json` | The same report as JSON, for automation and for building reports |
| `<prefix>_results.zip` | All four files above in one archive. **This is the file to send to Coralogix.** |

The summary contains:

- headline GB/day and events/day, with peak, p95 and monthly figures
- shippable GB/day (Standard class), GB/day that needs changes (Infrequent Access or Delivery class), and GB/day from log groups that were deleted
- subscription filter usage, with `--check-subscriptions`
- breakdowns by account, region and log group prefix (Lambda, EKS, Container Insights, ECS, RDS, API Gateway, WAF, Route 53, Other)
- the top 25 log groups by bytes
- the daily trend for the organization
- every region that was not fully scanned, with the reason
- notes and API usage

The four report files are kept next to the zip so you can review them before sending. All files are written as UTF-8 (the zip is compressed with deflate) to a temporary file, then renamed into place. If you interrupt the run with Ctrl+C, the tool still writes partial results and the zip, marked `interrupted: true`. Output files contain customer data and are listed in `.gitignore`.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every region was measured. Regions that are disabled or blocked by an SCP are allowed. |
| 1 | Invalid arguments, or nothing could be scanned |
| 2 | Finished, but some accounts or regions failed. See *NOT FULLY SCANNED*. |
| 130 | Interrupted. Partial results were written. |

## Cost

`GetMetricData` costs about $0.01 per 1,000 metrics requested. Each log group needs 2 metrics, plus 2 per region, so 50,000 log groups cost about $1. The other API calls are free. Before the metrics phase, the tool prints the estimated cost. It asks for confirmation only if stdin is a terminal and the estimate is above $5, so CI and agent runs never wait for input.

## IAM role

`iam_log_sizing_role.yaml` creates a read-only role, `CoralogixLogSizingRole`, with these permissions:

| Action | Required |
| --- | --- |
| `logs:DescribeLogGroups` | yes |
| `cloudwatch:GetMetricData` | yes |
| `ec2:DescribeRegions` | yes (without it, the tool tries every region the SDK knows) |
| `iam:ListAccountAliases` | no, used for account names |
| `logs:DescribeSubscriptionFilters` | only with `--check-subscriptions` |

`sts:GetCallerIdentity` needs no permission. The template takes these parameters:

- `TrustedAccountId`: the account that runs the tool.
- `TrustedPrincipalArn` (optional): limits the trust to one principal. Wildcards are allowed.
- `RoleName`: the role name, `CoralogixLogSizingRole` by default.

`MaxSessionDuration` is 3600 seconds, the most AWS allows for chained role sessions such as SSO assuming another role. Deploy the template to member accounts with a StackSet, as shown in [INSTRUCTIONS.md](INSTRUCTIONS.md).

## Limitations

- Only CloudWatch Logs is covered. Logs that AWS services write directly to S3 or Firehose, such as ELB access logs, CloudTrail to S3 and VPC Flow Logs to S3, are not counted.
- `IncomingBytes` is the size CloudWatch reports at ingestion. The size Coralogix bills can differ slightly after parsing and enrichment.
- Log groups deleted during the window appear only in the account-level totals, not in the per-log-group breakdown.
- `IncomingBytes` and `IncomingLogEvents` are published only for log groups that received data, so log groups with no data show 0.

## Development

```bash
python3 -m pip install boto3 pytest
```

```bash
TZ=Asia/Jerusalem python3 -m pytest -q
```

The tests use botocore `Stubber` and fake clients, so they need no AWS access. They are run in a non-UTC time zone to catch day-boundary bugs.
