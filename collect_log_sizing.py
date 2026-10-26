#!/usr/bin/env python3
"""
CloudWatch Logs ingestion sizing for Coralogix.

Measures, for every log group in every account and enabled region:
  - ingested bytes    (AWS/Logs IncomingBytes, uncompressed size at ingestion)
  - log event count   (AWS/Logs IncomingLogEvents)
as daily sums over a lookback window of complete UTC days (default 30).

Read-only. Uses log group metadata and CloudWatch metrics only; it never reads
log events (no GetLogEvents, FilterLogEvents or Logs Insights).

Usage:
    # The account behind your current credentials
    python collect_log_sizing.py

    # Named CLI profiles (one account per profile)
    python collect_log_sizing.py --profiles prod staging

    # Cross-account role, accounts from a file or from AWS Organizations
    python collect_log_sizing.py --role-name CoralogixLogSizingRole --accounts-file accounts.json
    python collect_log_sizing.py --role-name CoralogixLogSizingRole

    # Check permissions in one account/region and stop
    python collect_log_sizing.py --role-name CoralogixLogSizingRole --accounts-file accounts.json --preflight

Required permissions in each scanned account (see iam_log_sizing_role.yaml):
    logs:DescribeLogGroups, cloudwatch:GetMetricData, ec2:DescribeRegions
    optional: iam:ListAccountAliases, logs:DescribeSubscriptionFilters (--check-subscriptions)
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 9):
    sys.exit("collect_log_sizing.py requires Python 3.9 or newer (found %d.%d)." % sys.version_info[:2])

import argparse
import csv
import hashlib
import json
import math
import os
import re
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import boto3
    import botocore
    import botocore.exceptions
    import botocore.session
    from botocore.config import Config
    from botocore.credentials import RefreshableCredentials
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        ProfileNotFound,
    )
except ImportError:
    sys.exit("boto3 is required. Install it with: pip install -r requirements.txt")

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None


TOOL_NAME = "coralogix-log-sizing"
TOOL_VERSION = "1.0.0"
MIN_BOTO3 = (1, 34)

GB = 1_000_000_000
MAX_QUERIES_PER_CALL = 500
MAX_LOOKBACK_DAYS = 455
MAX_WORKERS = 50
GMD_USD_PER_1000_METRICS = 0.01
CONFIRM_COST_THRESHOLD_USD = 5.0
GAP_WARN_FRACTION = 0.05
GMD_RETRY_ATTEMPTS = 3
ROLE_SESSION_NAME = "CoralogixLogSizing"
ROLE_SESSION_SECONDS = 3600
TOP_LOG_GROUPS = 25

PARTITION_HOME_REGION = {"aws": "us-east-1", "aws-us-gov": "us-gov-west-1", "aws-cn": "cn-north-1"}
PARTITION_DNS_SUFFIX = {"aws": "amazonaws.com", "aws-us-gov": "amazonaws.com", "aws-cn": "amazonaws.com.cn"}

STATUS_OK = "ok"
STATUS_ACCESS_DENIED = "access_denied"
STATUS_SCP_DENIED = "scp_denied"
STATUS_THROTTLED = "throttled"
STATUS_PARTIAL = "partial"
STATUS_REGION_DISABLED = "region_disabled"
STATUS_ERROR = "error"
STATUS_NOT_RUN = "not_run"
FAILURE_STATUSES = {STATUS_ACCESS_DENIED, STATUS_THROTTLED, STATUS_PARTIAL, STATUS_ERROR, STATUS_NOT_RUN}

ACCESS_DENIED_CODES = {
    "AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
    "UnauthorizedAccess", "AuthorizationError", "Forbidden",
}
THROTTLE_CODES = {
    "Throttling", "ThrottlingException", "ThrottledException", "TooManyRequestsException",
    "RequestLimitExceeded", "RequestThrottled", "RequestThrottledException",
    "ProvisionedThroughputExceededException", "LimitExceededException", "SlowDown",
}
TOKEN_REJECTED_CODES = {
    "UnrecognizedClientException", "InvalidClientTokenId", "AuthFailure",
    "ExpiredToken", "ExpiredTokenException", "InvalidToken", "SignatureDoesNotMatch",
}
SSO_ERRORS = tuple(
    getattr(botocore.exceptions, name)
    for name in ("SSOError", "SSOTokenLoadError", "UnauthorizedSSOTokenError", "TokenRetrievalError")
    if hasattr(botocore.exceptions, name)
)

CATEGORY_PREFIXES: List[Tuple[str, Tuple[str, ...]]] = [
    ("Lambda", ("/aws/lambda/",)),
    ("EKS", ("/aws/eks/",)),
    ("Container Insights", ("/aws/containerinsights/",)),
    ("ECS", ("/ecs/", "/aws/ecs/")),
    ("RDS", ("/aws/rds/",)),
    ("API Gateway", ("API-Gateway-Execution-Logs_", "/aws/apigateway/")),
    ("WAF", ("aws-waf-logs-",)),
    ("Route 53", ("/aws/route53/",)),
]
CATEGORY_OTHER = "Other"

# Per https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html
CLASS_SHIPPABILITY = {
    "STANDARD": (True, ""),
    "INFREQUENT_ACCESS": (False, "Infrequent Access class does not support subscription filters"),
    "DELIVERY": (False, "Delivery class only forwards Lambda logs to S3/Firehose; ship from that destination"),
}

REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
ACCOUNT_ID_RE = re.compile(r"^\d{12}$")


# ---------------------------------------------------------------------------
# API usage accounting (shared across threads)
# ---------------------------------------------------------------------------

class Usage:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.gmd_calls = 0
        self.gmd_metrics = 0
        self.throttle_retries = 0

    def add_gmd(self, metrics: int) -> None:
        with self._lock:
            self.gmd_calls += 1
            self.gmd_metrics += metrics

    def add_throttle(self) -> None:
        with self._lock:
            self.throttle_retries += 1

    @property
    def gmd_cost_usd(self) -> float:
        return self.gmd_metrics / 1000.0 * GMD_USD_PER_1000_METRICS


USAGE = Usage()

CLIENT_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 10},
    connect_timeout=10,
    read_timeout=60,
    max_pool_connections=10,
    user_agent_extra=f"{TOOL_NAME}/{TOOL_VERSION}",
)


def _count_throttles(response=None, **kwargs) -> None:
    if response:
        code = (response[1] or {}).get("Error", {}).get("Code")
        if code in THROTTLE_CODES:
            USAGE.add_throttle()


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

def _short(text: str, limit: int = 300) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def is_token_rejected(exc: BaseException) -> bool:
    return isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") in TOKEN_REJECTED_CODES


def classify_error(exc: BaseException, profile: Optional[str] = None) -> Tuple[str, str]:
    """Map an exception to (status, human-readable message)."""
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "")
        msg = err.get("Message", "")
        op = exc.operation_name or "request"
        if code in ACCESS_DENIED_CODES or "AccessDenied" in code:
            if "service control policy" in msg.lower():
                return STATUS_SCP_DENIED, f"{op}: blocked by a service control policy"
            return STATUS_ACCESS_DENIED, _short(f"{op}: {code}: {msg}")
        if code in THROTTLE_CODES:
            return STATUS_THROTTLED, _short(f"{op}: throttled after retries ({code})")
        if code in TOKEN_REJECTED_CODES:
            return STATUS_ERROR, _short(
                f"{op}: {code}: credentials were rejected (expired session, or the region is not enabled)"
            )
        return STATUS_ERROR, _short(f"{op}: {code}: {msg}")
    if SSO_ERRORS and isinstance(exc, SSO_ERRORS):
        hint = f"aws sso login --profile {profile}" if profile else "aws sso login"
        return STATUS_ERROR, f"SSO session expired or missing; run: {hint}"
    if isinstance(exc, ProfileNotFound):
        return STATUS_ERROR, f"AWS profile not found: {exc}"
    if isinstance(exc, NoCredentialsError):
        return STATUS_ERROR, "No AWS credentials found (configure a profile, SSO, or environment credentials)"
    if isinstance(exc, EndpointConnectionError):
        return STATUS_ERROR, _short(f"Could not reach AWS endpoint ({exc}); check network or proxy settings")
    if isinstance(exc, BotoCoreError):
        return STATUS_ERROR, _short(f"{type(exc).__name__}: {exc}")
    return STATUS_ERROR, _short(f"{type(exc).__name__}: {exc}")


class UsageError(Exception):
    """Invalid input; reported to the user and exits with code 1."""


# ---------------------------------------------------------------------------
# Sessions and clients
# ---------------------------------------------------------------------------

def new_session(credentials: Any, region: str, profile: Optional[str] = None) -> boto3.Session:
    """A fresh boto3 session per task: boto3 sessions are not thread-safe, but
    botocore credential objects (including refreshable ones) are, so one is shared."""
    bs = botocore.session.Session(profile=profile)
    bs._credentials = credentials
    return boto3.Session(botocore_session=bs, region_name=region)


def make_client(session: boto3.Session, service: str, region: str, endpoint_url: Optional[str] = None):
    client = session.client(service, region_name=region, config=CLIENT_CONFIG, endpoint_url=endpoint_url)
    client.meta.events.register("needs-retry", _count_throttles)
    return client


def regional_sts_client(session: boto3.Session, partition: str, region: str):
    # Tokens from the global STS endpoint are rejected in opt-in regions; regional ones are valid everywhere.
    suffix = PARTITION_DNS_SUFFIX.get(partition)
    endpoint = f"https://sts.{region}.{suffix}" if suffix else None
    return make_client(session, "sts", region, endpoint_url=endpoint)


@dataclass
class Caller:
    account_id: str
    arn: str
    partition: str
    home_region: str
    default_region: Optional[str]
    credentials: Any


def resolve_identity(session: boto3.Session) -> Tuple[str, str, str, str]:
    """Return (account_id, arn, partition, home_region) for a session's credentials."""
    region = session.region_name or "us-east-1"
    ident = make_client(session, "sts", region).get_caller_identity()
    arn = ident["Arn"]
    partition = arn.split(":")[1] if arn.count(":") >= 5 else "aws"
    home = PARTITION_HOME_REGION.get(partition) or region
    return ident["Account"], arn, partition, home


def resolve_caller() -> Caller:
    session = boto3.Session()
    credentials = session.get_credentials()
    if credentials is None:
        raise NoCredentialsError()
    account_id, arn, partition, home = resolve_identity(session)
    return Caller(account_id, arn, partition, home, session.region_name, credentials)


def role_credentials(caller: Caller, account_id: str, role_name: str) -> RefreshableCredentials:
    """Assume the role now and return credentials that re-assume it before expiry."""
    role_arn = f"arn:{caller.partition}:iam::{account_id}:role/{role_name}"
    sts = regional_sts_client(new_session(caller.credentials, caller.home_region), caller.partition, caller.home_region)

    def fetch() -> dict:
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName=ROLE_SESSION_NAME, DurationSeconds=ROLE_SESSION_SECONDS,
        )["Credentials"]
        return {
            "access_key": creds["AccessKeyId"],
            "secret_key": creds["SecretAccessKey"],
            "token": creds["SessionToken"],
            "expiry_time": creds["Expiration"].astimezone(timezone.utc).isoformat(),
        }

    return RefreshableCredentials.create_from_metadata(
        metadata=fetch(), refresh_using=fetch, method="sts-assume-role",
    )


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Account:
    id: str
    name: str
    profile: Optional[str] = None
    credentials: Any = None
    auth: str = ""
    partition: str = "aws"
    home_region: str = "us-east-1"
    default_region: Optional[str] = None
    regions: List[str] = field(default_factory=list)
    disabled_regions: List[str] = field(default_factory=list)
    region_source: str = ""
    status: str = STATUS_OK
    error: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.credentials is not None and self.status == STATUS_OK


@dataclass
class LogGroup:
    name: str
    log_class: str
    category: str
    shippable: bool
    shippable_reason: str
    bytes_daily: List[float] = field(default_factory=list)
    events_daily: List[float] = field(default_factory=list)
    metric_status: str = STATUS_NOT_RUN
    subscription_filters: Optional[int] = None
    subscription_destinations: List[str] = field(default_factory=list)
    subscription_status: str = ""

    @property
    def bytes_total(self) -> float:
        return sum(self.bytes_daily)

    @property
    def events_total(self) -> float:
        return sum(self.events_daily)

    @property
    def active(self) -> bool:
        return self.bytes_total > 0 or self.events_total > 0


@dataclass
class RegionResult:
    account_id: str
    account_name: str
    region: str
    auth: str = ""
    status: str = STATUS_NOT_RUN
    error: str = ""
    log_groups: List[LogGroup] = field(default_factory=list)
    inventory_done: bool = False
    metrics_done: bool = False
    account_bytes_daily: Optional[List[float]] = None
    account_events_daily: Optional[List[float]] = None
    partial_log_groups: int = 0
    notes: List[str] = field(default_factory=list)

    def fail(self, status: str, error: str) -> None:
        if self.status in (STATUS_OK, STATUS_NOT_RUN, STATUS_PARTIAL) or not self.error:
            self.status = status
            self.error = error

    @property
    def group_bytes(self) -> float:
        return sum(g.bytes_total for g in self.log_groups)

    @property
    def group_events(self) -> float:
        return sum(g.events_total for g in self.log_groups)

    @property
    def total_bytes(self) -> float:
        return sum(self.account_bytes_daily) if self.account_bytes_daily is not None else 0.0

    @property
    def total_events(self) -> float:
        return sum(self.account_events_daily) if self.account_events_daily is not None else 0.0


@dataclass
class Window:
    start: datetime
    end: datetime
    days: int
    dates: List[date] = field(init=False)

    def __post_init__(self) -> None:
        self.dates = [(self.start + timedelta(days=i)).date() for i in range(self.days)]


def compute_window(days: int, now: Optional[datetime] = None) -> Window:
    """Complete UTC days only: [today 00:00 UTC - days, today 00:00 UTC)."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    end = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return Window(start=end - timedelta(days=days), end=end, days=days)


def categorize(name: str) -> Tuple[str, str]:
    for category, prefixes in CATEGORY_PREFIXES:
        for prefix in prefixes:
            if name.startswith(prefix):
                return category, prefix
    return CATEGORY_OTHER, ""


def shippability(log_class: str) -> Tuple[bool, str]:
    return CLASS_SHIPPABILITY.get(log_class, (False, f"Unknown log group class {log_class!r}"))


# ---------------------------------------------------------------------------
# Account resolution
# ---------------------------------------------------------------------------

def load_accounts_file(path: str) -> List[dict]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise UsageError(f"--accounts-file not found: {path}")
    except json.JSONDecodeError as e:
        raise UsageError(f"--accounts-file is not valid JSON ({path}): {e}")
    if not isinstance(data, list) or not data:
        raise UsageError('--accounts-file must be a non-empty JSON list like [{"id": "123456789012", "name": "prod"}]')
    accounts, seen = [], set()
    for i, item in enumerate(data):
        if not isinstance(item, dict) or "id" not in item:
            raise UsageError(f"--accounts-file entry {i} must be an object with an \"id\" key")
        raw = item["id"]
        if not isinstance(raw, str):
            raise UsageError(
                f"--accounts-file entry {i}: account id {raw!r} must be a quoted string "
                "(numbers lose leading zeros)"
            )
        acct_id = raw.strip()
        if not ACCOUNT_ID_RE.match(acct_id):
            raise UsageError(f"--accounts-file entry {i}: {acct_id!r} is not a 12-digit AWS account id")
        if acct_id in seen:
            continue
        seen.add(acct_id)
        profile = item.get("profile")
        if profile is not None and not isinstance(profile, str):
            raise UsageError(f"--accounts-file entry {i}: \"profile\" must be a string")
        accounts.append({"id": acct_id, "name": str(item.get("name") or acct_id), "profile": profile})
    return accounts


def list_org_accounts(caller: Caller) -> List[dict]:
    org = make_client(new_session(caller.credentials, caller.home_region), "organizations", caller.home_region)
    accounts = []
    for page in org.get_paginator("list_accounts").paginate():
        for acct in page.get("Accounts", []):
            state = acct.get("State") or acct.get("Status")
            if state == "ACTIVE":
                accounts.append({"id": acct["Id"], "name": acct.get("Name") or acct["Id"], "profile": None})
    return accounts


def account_alias(acct: Account) -> Optional[str]:
    try:
        iam = make_client(new_session(acct.credentials, acct.home_region, acct.profile), "iam", acct.home_region)
        aliases = iam.list_account_aliases().get("AccountAliases", [])
        return aliases[0] if aliases else None
    except (ClientError, BotoCoreError):
        return None


def resolve_profile_account(profile: str, name: Optional[str] = None) -> Account:
    try:
        session = boto3.Session(profile_name=profile)
        credentials = session.get_credentials()
        if credentials is None:
            raise NoCredentialsError()
        account_id, _arn, partition, home = resolve_identity(session)
    except Exception as e:
        status, msg = classify_error(e, profile)
        return Account(id="-", name=name or profile, profile=profile, status=status,
                       error=f"profile '{profile}': {msg}")
    acct = Account(id=account_id, name=name or profile, profile=profile, credentials=credentials,
                   auth=f"profile:{profile}", partition=partition, home_region=home,
                   default_region=session.region_name)
    if not name:
        acct.name = account_alias(acct) or profile
    return acct


def resolve_accounts(args: argparse.Namespace) -> Tuple[str, List[Account], Optional[Caller]]:
    """Return (mode, accounts, caller). Profile-mode accounts are fully prepared here."""
    if args.profiles:
        accounts, seen = [], {}
        for p in dict.fromkeys(args.profiles):
            acct = resolve_profile_account(p)
            if acct.id != "-" and acct.id in seen:
                print(f"  Note: profile '{p}' is the same account as '{seen[acct.id]}' ({acct.id}); scanning once")
                continue
            seen[acct.id] = p
            accounts.append(acct)
        return "profiles", accounts, None

    if args.accounts_file and not args.role_name:
        entries = load_accounts_file(args.accounts_file)
        missing = [e["id"] for e in entries if not e["profile"]]
        if missing:
            raise UsageError(
                f"{len(missing)} --accounts-file entries have no \"profile\" key (e.g. {missing[0]}). "
                "Add --role-name to scan them by assuming a role."
            )
        accounts = [resolve_profile_account(e["profile"], e["name"]) for e in entries]
        return "profiles", accounts, None

    caller = resolve_caller()

    if args.role_name:
        if args.accounts_file:
            entries = load_accounts_file(args.accounts_file)
        else:
            print("Listing active accounts from AWS Organizations...")
            try:
                entries = list_org_accounts(caller)
            except ClientError as e:
                status, msg = classify_error(e)
                raise UsageError(
                    f"Could not list Organization accounts ({msg}).\n"
                    "  organizations:ListAccounts only works from the management or a delegated-admin account.\n"
                    "  Use --accounts-file (see discover_accounts.py) or --profiles instead."
                )
        accounts = [
            Account(id=e["id"], name=e["name"], partition=caller.partition, home_region=caller.home_region,
                    default_region=caller.default_region)
            for e in entries
        ]
        return "role", accounts, caller

    acct = Account(id=caller.account_id, name=caller.account_id, credentials=caller.credentials,
                   auth="caller_credentials", partition=caller.partition, home_region=caller.home_region,
                   default_region=caller.default_region)
    acct.name = account_alias(acct) or caller.account_id
    return "caller", [acct], caller


def discover_regions(acct: Account, requested: Optional[List[str]]) -> None:
    enabled: Optional[List[str]] = None
    last_error: Optional[BaseException] = None
    for region in dict.fromkeys(r for r in (acct.home_region, acct.default_region) if r):
        try:
            ec2 = make_client(new_session(acct.credentials, region, acct.profile), "ec2", region)
            resp = ec2.describe_regions(AllRegions=False)
            enabled = sorted(
                r["RegionName"] for r in resp.get("Regions", [])
                if r.get("OptInStatus") in (None, "opt-in-not-required", "opted-in")
            )
            break
        except Exception as e:
            last_error = e

    if enabled is not None:
        acct.region_source = "describe_regions"
        if requested:
            acct.regions = [r for r in requested if r in enabled]
            acct.disabled_regions = [r for r in requested if r not in enabled]
        else:
            acct.regions = enabled
        return

    _status, msg = classify_error(last_error) if last_error else (STATUS_ERROR, "unknown error")
    if requested:
        acct.regions = list(requested)
        acct.region_source = "requested"
    else:
        acct.regions = sorted(boto3.Session().get_available_regions("logs", partition_name=acct.partition))
        acct.region_source = "fallback"
    acct.notes.append(
        f"ec2:DescribeRegions failed ({msg}); scanning {len(acct.regions)} region(s) from "
        f"{'--regions' if requested else 'the SDK region list'}"
    )


def prepare_account(acct: Account, mode: str, caller: Optional[Caller], args: argparse.Namespace) -> Account:
    if acct.status != STATUS_OK:
        return acct
    try:
        if mode == "role":
            assert caller is not None
            try:
                acct.credentials = role_credentials(caller, acct.id, args.role_name)
                acct.auth = f"role:{args.role_name}"
            except Exception as e:
                if acct.id == caller.account_id:
                    acct.credentials = caller.credentials
                    acct.auth = "caller_credentials"
                    acct.notes.append(f"Role {args.role_name} not assumable in the caller's own account; "
                                      "used the caller's credentials instead")
                else:
                    status, msg = classify_error(e)
                    acct.status = status
                    acct.error = f"Could not assume role {args.role_name}: {msg}"
                    return acct
            if acct.name == acct.id:
                acct.name = account_alias(acct) or acct.id
        discover_regions(acct, args.regions)
    except Exception as e:
        acct.status, acct.error = classify_error(e, acct.profile)
    return acct


# ---------------------------------------------------------------------------
# Collection: inventory
# ---------------------------------------------------------------------------

def _region_failure_status(acct: Account, exc: BaseException) -> Tuple[str, str]:
    status, msg = classify_error(exc, acct.profile)
    if acct.region_source == "fallback" and is_token_rejected(exc):
        return STATUS_REGION_DISABLED, "region not enabled for this account"
    return status, msg


def collect_inventory(acct: Account, rr: RegionResult) -> RegionResult:
    try:
        logs = make_client(new_session(acct.credentials, rr.region, acct.profile), "logs", rr.region)
        groups: List[LogGroup] = []
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate(PaginationConfig={"PageSize": 50}):
            for g in page.get("logGroups", []):
                name = g["logGroupName"]
                log_class = g.get("logGroupClass") or "STANDARD"
                category, _ = categorize(name)
                ok, reason = shippability(log_class)
                groups.append(LogGroup(name=name, log_class=log_class, category=category,
                                       shippable=ok, shippable_reason=reason))
        rr.log_groups = groups
        rr.inventory_done = True  # status stays not_run until metrics are collected
    except Exception as e:
        rr.fail(*_region_failure_status(acct, e))
    return rr


# ---------------------------------------------------------------------------
# Collection: metrics
# ---------------------------------------------------------------------------

def metric_query(query_id: str, metric: str, log_group: Optional[str]) -> dict:
    dims = [{"Name": "LogGroupName", "Value": log_group}] if log_group is not None else []
    return {
        "Id": query_id,
        "MetricStat": {
            "Metric": {"Namespace": "AWS/Logs", "MetricName": metric, "Dimensions": dims},
            "Period": 86400,
            "Stat": "Sum",
        },
        "ReturnData": True,
    }


def build_queries(log_groups: Sequence[LogGroup]) -> List[dict]:
    queries = [metric_query("tb", "IncomingBytes", None), metric_query("te", "IncomingLogEvents", None)]
    for i, g in enumerate(log_groups):
        queries.append(metric_query(f"b{i}", "IncomingBytes", g.name))
        queries.append(metric_query(f"e{i}", "IncomingLogEvents", g.name))
    return queries


def chunked(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def run_get_metric_data(cw, queries: Sequence[dict], window: Window) -> Tuple[Dict[str, Dict[date, float]], Dict[str, str], List[dict]]:
    """Run one GetMetricData request (all NextToken pages). Returns per-Id {utc_day: value},
    per-Id final status, and Messages. A query can be split across pages, so pages are merged."""
    series: Dict[str, Dict[date, float]] = {q["Id"]: {} for q in queries}
    status: Dict[str, str] = {}
    last_page: Dict[str, int] = {}
    messages: List[dict] = []
    kwargs: Dict[str, Any] = dict(
        MetricDataQueries=list(queries), StartTime=window.start, EndTime=window.end, ScanBy="TimestampAscending",
    )
    page = 0
    while True:
        resp = cw.get_metric_data(**kwargs)
        USAGE.add_gmd(len(queries))
        for r in resp.get("MetricDataResults", []):
            qid = r["Id"]
            points = series.setdefault(qid, {})
            for ts, value in zip(r.get("Timestamps", []), r.get("Values", [])):
                points[ts.astimezone(timezone.utc).date()] = float(value)
            status[qid] = r.get("StatusCode", "Complete")
            last_page[qid] = page
        messages.extend(resp.get("Messages", []) or [])
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
        page += 1
    for qid, st in list(status.items()):
        # PartialData on an earlier page just means "continued on the next page".
        if st == "PartialData" and last_page[qid] < page:
            status[qid] = "Complete"
    for q in queries:
        status.setdefault(q["Id"], "Complete")
    return series, status, messages


def fetch_metrics(cw, queries: Sequence[dict], window: Window,
                  sleep: Callable[[float], None] = time.sleep) -> Tuple[Dict[str, Dict[date, float]], Dict[str, str], List[dict]]:
    """Batch queries (500 per call) and retry PartialData/InternalError results."""
    all_series: Dict[str, Dict[date, float]] = {}
    all_status: Dict[str, str] = {}
    all_messages: List[dict] = []
    for batch in chunked(list(queries), MAX_QUERIES_PER_CALL):
        pending = list(batch)
        for attempt in range(GMD_RETRY_ATTEMPTS):
            series, status, messages = run_get_metric_data(cw, pending, window)
            all_messages.extend(messages)
            for q in pending:
                all_series[q["Id"]] = series.get(q["Id"], {})
                all_status[q["Id"]] = status[q["Id"]]
            retry = [q for q in pending if status[q["Id"]] in ("PartialData", "InternalError")]
            if not retry or attempt == GMD_RETRY_ATTEMPTS - 1:
                break
            pending = retry
            sleep(2 ** attempt)
    return all_series, all_status, all_messages


def to_daily(points: Dict[date, float], window: Window) -> List[float]:
    return [points.get(d, 0.0) for d in window.dates]


def collect_metrics(acct: Account, rr: RegionResult, window: Window) -> RegionResult:
    try:
        cw = make_client(new_session(acct.credentials, rr.region, acct.profile), "cloudwatch", rr.region)
        queries = build_queries(rr.log_groups)
        series, status, messages = fetch_metrics(cw, queries, window)
    except Exception as e:
        rr.fail(*_region_failure_status(acct, e))
        return rr

    forbidden = [qid for qid, st in status.items() if st == "Forbidden"]
    if forbidden:
        rr.fail(STATUS_ACCESS_DENIED, f"GetMetricData returned Forbidden for {len(forbidden)} metric queries")
        return rr

    def incomplete(qid: str) -> bool:
        return status.get(qid) in ("PartialData", "InternalError")

    rr.account_bytes_daily = to_daily(series.get("tb", {}), window)
    rr.account_events_daily = to_daily(series.get("te", {}), window)
    partial = 1 if incomplete("tb") or incomplete("te") else 0
    for i, g in enumerate(rr.log_groups):
        g.bytes_daily = to_daily(series.get(f"b{i}", {}), window)
        g.events_daily = to_daily(series.get(f"e{i}", {}), window)
        if incomplete(f"b{i}") or incomplete(f"e{i}"):
            g.metric_status = STATUS_PARTIAL
            partial += 1
        else:
            g.metric_status = STATUS_OK
    rr.metrics_done = True
    if rr.status == STATUS_NOT_RUN:
        rr.status = STATUS_OK
    rr.partial_log_groups = partial
    for m in messages:
        rr.notes.append(_short(f"GetMetricData message {m.get('Code')}: {m.get('Value')}"))
    if partial:
        rr.fail(STATUS_PARTIAL, f"{partial} metric series still incomplete after {GMD_RETRY_ATTEMPTS} attempts")
    return rr


# ---------------------------------------------------------------------------
# Collection: subscription filters (optional)
# ---------------------------------------------------------------------------

def destination_type(arn: str) -> str:
    parts = arn.split(":")
    service = parts[2] if len(parts) > 2 else ""
    return {"lambda": "lambda", "firehose": "firehose", "kinesis": "kinesis", "logs": "logs_destination"}.get(
        service, service or "unknown")


def collect_subscriptions(acct: Account, rr: RegionResult) -> RegionResult:
    try:
        logs = make_client(new_session(acct.credentials, rr.region, acct.profile), "logs", rr.region)
    except Exception as e:
        rr.notes.append(f"subscription check skipped: {classify_error(e, acct.profile)[1]}")
        return rr
    paginator = logs.get_paginator("describe_subscription_filters")
    denied: Optional[str] = None
    for g in rr.log_groups:
        if not (g.active and g.log_class == "STANDARD"):
            continue
        if denied:
            g.subscription_status = denied
            continue
        try:
            destinations = []
            for page in paginator.paginate(logGroupName=g.name):
                destinations.extend(f.get("destinationArn", "") for f in page.get("subscriptionFilters", []))
            g.subscription_filters = len(destinations)
            g.subscription_destinations = destinations
            g.subscription_status = STATUS_OK
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                g.subscription_status = "log group no longer exists"
                continue
            status, msg = classify_error(e, acct.profile)
            g.subscription_status = status
            if status in (STATUS_ACCESS_DENIED, STATUS_SCP_DENIED):
                denied = status
                rr.notes.append(f"subscription check: {msg}")
        except Exception as e:
            g.subscription_status = classify_error(e, acct.profile)[0]
    return rr


# ---------------------------------------------------------------------------
# Parallel execution with progress
# ---------------------------------------------------------------------------

class Progress:
    def __init__(self, total: int, label: str) -> None:
        self.total, self.label, self.done = total, label, 0
        self.bar = tqdm(total=total, desc=label, unit="task") if tqdm and sys.stderr.isatty() else None
        self.step = max(1, math.ceil(total / 4))

    def update(self) -> None:
        self.done += 1
        if self.bar:
            self.bar.update(1)
        elif self.done == self.total or self.done % self.step == 0:
            print(f"  {self.label}: {self.done}/{self.total}", flush=True)

    def close(self) -> None:
        if self.bar:
            self.bar.close()


def run_parallel(items: Sequence[Any], fn: Callable[[Any], Any], workers: int, label: str,
                 on_error: Callable[[Any, BaseException], None]) -> None:
    if not items:
        return
    progress = Progress(len(items), label)
    executor = ThreadPoolExecutor(max_workers=min(workers, len(items)))
    try:
        futures = {executor.submit(fn, item): item for item in items}
        for fut in as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                on_error(futures[fut], e)
            progress.update()
    except KeyboardInterrupt:
        executor.shutdown(wait=False, cancel_futures=True)
        progress.close()
        raise
    executor.shutdown(wait=True)
    progress.close()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def gb(value: float) -> float:
    return value / GB


def percentile(values: Sequence[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100.0 * len(ordered)))
    return ordered[rank - 1]


def redact_name(name: str) -> str:
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    _, prefix = categorize(name)
    return f"{prefix}{digest}"


def redact_arn(arn: str) -> str:
    """Keep partition, account and resource type; hash the principal name."""
    head, sep, resource = arn.rpartition(":")
    kind, slash, name = resource.partition("/")
    if not slash:
        return arn
    return f"{head}{sep}{kind}/{hashlib.sha256(name.encode('utf-8')).hexdigest()[:12]}"


class Namer:
    def __init__(self, redact: bool) -> None:
        self.redact = redact

    def log_group(self, name: str) -> str:
        return redact_name(name) if self.redact else name

    def destinations(self, arns: Sequence[str]) -> str:
        if self.redact:
            return ";".join(destination_type(a) for a in arns)
        return ";".join(arns)


def _r(value: float, digits: int = 4) -> float:
    return round(value, digits)


def build_summary(results: Sequence[RegionResult], accounts: Sequence[Account], window: Window,
                  meta: dict, namer: Namer, check_subscriptions: bool) -> dict:
    days = window.days
    measured = [r for r in results if r.metrics_done]
    daily_bytes = [0.0] * days
    daily_events = [0.0] * days
    for r in measured:
        for i in range(days):
            daily_bytes[i] += r.account_bytes_daily[i]
            daily_events[i] += r.account_events_daily[i]
    total_bytes = sum(daily_bytes)
    total_events = sum(daily_events)
    group_bytes = sum(r.group_bytes for r in measured)
    group_events = sum(r.group_events for r in measured)
    avg_gb = gb(total_bytes) / days
    avg_events = total_events / days

    groups = [(r, g) for r in measured for g in r.log_groups]

    by_class: Dict[str, float] = {}
    for _, g in groups:
        by_class[g.log_class] = by_class.get(g.log_class, 0.0) + g.bytes_total
    shippable_bytes = sum(g.bytes_total for _, g in groups if g.shippable)
    needs_change_bytes = sum(g.bytes_total for _, g in groups if not g.shippable)
    unattributed_bytes = max(0.0, total_bytes - group_bytes)

    categories: Dict[str, dict] = {}
    for _, g in groups:
        c = categories.setdefault(g.category, {"log_groups": 0, "active_log_groups": 0, "bytes": 0.0, "events": 0.0})
        c["log_groups"] += 1
        c["active_log_groups"] += 1 if g.active else 0
        c["bytes"] += g.bytes_total
        c["events"] += g.events_total
    by_category = {
        name: {
            "log_groups": c["log_groups"],
            "active_log_groups": c["active_log_groups"],
            "avg_gb_per_day": _r(gb(c["bytes"]) / days),
            "avg_events_per_day": round(c["events"] / days),
            "share_of_bytes_pct": _r(100.0 * c["bytes"] / group_bytes, 2) if group_bytes else 0.0,
        }
        for name, c in sorted(categories.items(), key=lambda kv: -kv[1]["bytes"])
    }

    per_account: Dict[str, dict] = {}
    names = {a.id: a.name for a in accounts}
    for r in results:
        a = per_account.setdefault(r.account_id, {
            "name": names.get(r.account_id, r.account_name), "regions_scanned": 0, "regions_failed": 0,
            "log_groups": 0, "active_log_groups": 0, "bytes": 0.0, "events": 0.0, "shippable_bytes": 0.0,
        })
        if r.metrics_done:
            a["regions_scanned"] += 1
            a["log_groups"] += len(r.log_groups)
            a["active_log_groups"] += sum(1 for g in r.log_groups if g.active)
            a["bytes"] += r.total_bytes
            a["events"] += r.total_events
            a["shippable_bytes"] += sum(g.bytes_total for g in r.log_groups if g.shippable)
        if r.status in FAILURE_STATUSES:
            a["regions_failed"] += 1
    per_account_out = {
        acct_id: {
            "name": a["name"],
            "regions_scanned": a["regions_scanned"],
            "regions_failed": a["regions_failed"],
            "log_groups": a["log_groups"],
            "active_log_groups": a["active_log_groups"],
            "total_bytes": int(a["bytes"]),
            "total_events": int(a["events"]),
            "avg_gb_per_day": _r(gb(a["bytes"]) / days),
            "avg_events_per_day": round(a["events"] / days),
            "shippable_gb_per_day": _r(gb(a["shippable_bytes"]) / days),
        }
        for acct_id, a in sorted(per_account.items(), key=lambda kv: -kv[1]["bytes"])
    }

    per_region: Dict[str, dict] = {}
    for r in measured:
        p = per_region.setdefault(r.region, {"bytes": 0.0, "events": 0.0, "log_groups": 0})
        p["bytes"] += r.total_bytes
        p["events"] += r.total_events
        p["log_groups"] += len(r.log_groups)
    per_region_out = {
        region: {
            "log_groups": p["log_groups"],
            "avg_gb_per_day": _r(gb(p["bytes"]) / days),
            "avg_events_per_day": round(p["events"] / days),
        }
        for region, p in sorted(per_region.items(), key=lambda kv: -kv[1]["bytes"])
    }

    top = sorted(groups, key=lambda rg: -rg[1].bytes_total)[:TOP_LOG_GROUPS]
    top_out = [
        {
            "account_id": r.account_id,
            "account_name": r.account_name,
            "region": r.region,
            "log_group": namer.log_group(g.name),
            "category": g.category,
            "log_group_class": g.log_class,
            "shippable": g.shippable,
            "avg_gb_per_day": _r(gb(g.bytes_total) / days),
            "peak_gb_per_day": _r(gb(max(g.bytes_daily or [0.0]))),
            "avg_events_per_day": round(g.events_total / days),
        }
        for r, g in top if g.bytes_total > 0
    ]

    status_counts: Dict[str, int] = {}
    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1
    issues = [
        {"account_id": r.account_id, "account_name": r.account_name, "region": r.region,
         "status": r.status, "error": r.error}
        for r in sorted(results, key=lambda x: (x.account_id, x.region)) if r.status != STATUS_OK
    ]
    gaps = []
    for r in measured:
        if r.total_bytes > 0:
            gap = (r.total_bytes - r.group_bytes) / r.total_bytes
            if abs(gap) > GAP_WARN_FRACTION:
                gaps.append({"account_id": r.account_id, "region": r.region,
                             "account_level_gb": _r(gb(r.total_bytes)), "log_group_sum_gb": _r(gb(r.group_bytes)),
                             "gap_pct": _r(100.0 * gap, 2)})
    notes = []
    for a in accounts:
        notes.extend(f"{a.id} ({a.name}): {n}" for n in a.notes)
    for r in results:
        notes.extend(f"{r.account_id}/{r.region}: {n}" for n in r.notes)

    subscriptions = None
    if check_subscriptions:
        checked = [(r, g) for r, g in groups if g.subscription_status == STATUS_OK]
        dest_counts: Dict[str, int] = {}
        for _, g in checked:
            for d in g.subscription_destinations:
                t = destination_type(d)
                dest_counts[t] = dest_counts.get(t, 0) + 1
        full = [g for _, g in checked if (g.subscription_filters or 0) >= 2]
        subscriptions = {
            "eligible_log_groups": sum(1 for _, g in groups if g.active and g.log_class == "STANDARD"),
            "checked_log_groups": len(checked),
            "check_failed": sum(1 for _, g in groups if g.subscription_status not in ("", STATUS_OK)),
            "with_filters": sum(1 for _, g in checked if (g.subscription_filters or 0) >= 1),
            "both_slots_used": len(full),
            "both_slots_used_gb_per_day": _r(gb(sum(g.bytes_total for g in full)) / days),
            "destination_types": dest_counts,
        }

    scanned_accounts = {r.account_id for r in measured}
    return {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **meta,
        "window": {
            "start_utc": window.start.isoformat(), "end_utc": window.end.isoformat(),
            "days": days, "note": "complete UTC days; end is exclusive",
        },
        "scope": {
            "accounts_requested": len(accounts),
            "accounts_scanned": len(scanned_accounts),
            "account_regions_scanned": len(measured),
            "status_counts": status_counts,
        },
        "totals": {
            "total_bytes": int(total_bytes),
            "total_events": int(total_events),
            "avg_gb_per_day": _r(avg_gb),
            "peak_gb_per_day": _r(gb(max(daily_bytes or [0.0]))),
            "p95_gb_per_day": _r(gb(percentile(daily_bytes, 95))),
            "monthly_gb": _r(avg_gb * 30, 2),
            "avg_events_per_day": round(avg_events),
            "peak_events_per_day": round(max(daily_events or [0.0])),
            "monthly_events": round(avg_events * 30),
            "avg_event_bytes": round(total_bytes / total_events) if total_events else 0,
            "source": "account-level AWS/Logs metrics (includes log groups deleted during the window)",
            "log_group_sum_bytes": int(group_bytes),
            "log_group_sum_events": int(group_events),
        },
        "shippable": {
            "shippable_gb_per_day": _r(gb(shippable_bytes) / days),
            "needs_changes_gb_per_day": _r(gb(needs_change_bytes) / days),
            "unattributed_gb_per_day": _r(gb(unattributed_bytes) / days),
            "by_class_gb_per_day": {k: _r(gb(v) / days) for k, v in sorted(by_class.items())},
            "note": ("shippable = STANDARD class (supports subscription filters); unattributed = ingestion "
                     "into log groups that no longer exist"),
        },
        "subscriptions": subscriptions,
        "per_account": per_account_out,
        "per_region": per_region_out,
        "by_category": by_category,
        "top_log_groups": top_out,
        "daily_trend": [
            {"date": d.isoformat(), "bytes": int(b), "gb": _r(gb(b)), "events": int(e)}
            for d, b, e in zip(window.dates, daily_bytes, daily_events)
        ],
        "log_group_sum_gaps": gaps,
        "issues": issues,
        "notes": notes,
        "api_usage": {
            "get_metric_data_calls": USAGE.gmd_calls,
            "metrics_requested": USAGE.gmd_metrics,
            "estimated_cost_usd": round(USAGE.gmd_cost_usd, 4),
            "throttle_retries": USAGE.throttle_retries,
        },
    }


def render_text(summary: dict) -> str:
    t, s, w, sc = summary["totals"], summary["shippable"], summary["window"], summary["scope"]
    col = 40
    lines = [
        "=" * 72,
        "CLOUDWATCH LOGS INGESTION SIZING  (Coralogix)",
        f"Generated: {summary['generated_utc']}   Tool: {summary.get('tool_version', '')}",
        f"Window:    {w['start_utc'][:10]} to {w['end_utc'][:10]} (exclusive), {w['days']} complete UTC days",
        "=" * 72,
        f"{'Accounts requested / scanned:':<{col}} {sc['accounts_requested']} / {sc['accounts_scanned']}",
        f"{'Account-regions scanned:':<{col}} {sc['account_regions_scanned']}",
        f"{'Status counts:':<{col}} " + ", ".join(f"{k}={v}" for k, v in sorted(sc["status_counts"].items())),
        "",
        "INGESTION (all CloudWatch Logs)",
        "-" * 72,
        f"  {'Average GB/day:':<{col}} {t['avg_gb_per_day']:>14,.3f}",
        f"  {'Peak GB/day:':<{col}} {t['peak_gb_per_day']:>14,.3f}",
        f"  {'p95 GB/day:':<{col}} {t['p95_gb_per_day']:>14,.3f}",
        f"  {'Monthly GB (30 x average):':<{col}} {t['monthly_gb']:>14,.2f}",
        f"  {'Average events/day:':<{col}} {t['avg_events_per_day']:>14,}",
        f"  {'Peak events/day:':<{col}} {t['peak_events_per_day']:>14,}",
        f"  {'Monthly events (30 x average):':<{col}} {t['monthly_events']:>14,}",
        f"  {'Average event size (bytes):':<{col}} {t['avg_event_bytes']:>14,}",
        f"  {'Total bytes in window:':<{col}} {t['total_bytes']:>14,}",
        f"  {'Total events in window:':<{col}} {t['total_events']:>14,}",
        "",
        "SHIPPABLE TO CORALOGIX (subscription filters)",
        "-" * 72,
        f"  {'Shippable now (Standard class) GB/day:':<{col}} {s['shippable_gb_per_day']:>14,.3f}",
        f"  {'Needs changes (IA / Delivery) GB/day:':<{col}} {s['needs_changes_gb_per_day']:>14,.3f}",
        f"  {'Deleted log groups GB/day:':<{col}} {s['unattributed_gb_per_day']:>14,.3f}",
    ]
    sub = summary.get("subscriptions")
    if sub:
        lines += [
            f"  {'Active Standard log groups checked:':<{col}} {sub['checked_log_groups']:>14,}",
            f"  {'  with existing subscription filters:':<{col}} {sub['with_filters']:>14,}",
            f"  {'  both filter slots in use:':<{col}} {sub['both_slots_used']:>14,}",
            f"  {'  GB/day in groups with both slots used:':<{col}} {sub['both_slots_used_gb_per_day']:>14,.3f}",
        ]
        if sub["destination_types"]:
            lines.append("    existing destinations: " + ", ".join(
                f"{k}={v}" for k, v in sorted(sub["destination_types"].items())))
        if sub["check_failed"]:
            lines.append(f"    could not check {sub['check_failed']} log group(s); see notes")

    lines += ["", "PER ACCOUNT", "-" * 72,
              f"  {'Account':<38} {'GB/day':>10} {'events/day':>14} {'groups':>7}"]
    for acct_id, a in summary["per_account"].items():
        label = _short(acct_id if a["name"] == acct_id else f"{a['name']} ({acct_id})", 38)
        lines.append(f"  {label:<38} {a['avg_gb_per_day']:>10,.3f} {a['avg_events_per_day']:>14,} "
                     f"{a['log_groups']:>7,}")

    lines += ["", "PER REGION", "-" * 72,
              f"  {'Region':<38} {'GB/day':>10} {'events/day':>14} {'groups':>7}"]
    empty = 0
    for region, p in summary["per_region"].items():
        if not p["log_groups"] and not p["avg_gb_per_day"] and not p["avg_events_per_day"]:
            empty += 1
            continue
        lines.append(f"  {region:<38} {p['avg_gb_per_day']:>10,.3f} {p['avg_events_per_day']:>14,} "
                     f"{p['log_groups']:>7,}")
    if empty:
        lines.append(f"  ({empty} scanned region(s) with no log groups and no ingestion not shown)")

    lines += ["", "BY LOG GROUP PREFIX", "-" * 72]
    for name, c in summary["by_category"].items():
        lines.append(f"  {name:<30} {c['avg_gb_per_day']:>10,.3f} GB/day {c['share_of_bytes_pct']:>6.1f}%  "
                     f"{c['active_log_groups']:,}/{c['log_groups']:,} active")

    lines += ["", f"TOP {TOP_LOG_GROUPS} LOG GROUPS BY BYTES", "-" * 72]
    for g in summary["top_log_groups"]:
        lines.append(f"  {g['avg_gb_per_day']:>10,.3f} GB/day  {g['account_id']} {g['region']:<15} "
                     f"{_short(g['log_group'], 60)}")

    if summary["log_group_sum_gaps"]:
        lines += ["", "ACCOUNT-LEVEL vs LOG GROUP SUM (gap > 5%, usually deleted log groups)", "-" * 72]
        for gp in summary["log_group_sum_gaps"]:
            lines.append(f"  {gp['account_id']} {gp['region']:<15} account={gp['account_level_gb']:,.3f} GB "
                         f"groups={gp['log_group_sum_gb']:,.3f} GB gap={gp['gap_pct']}%")

    issues = summary["issues"]
    if issues:
        lines += ["", f"NOT FULLY SCANNED ({len(issues)})", "-" * 72]
        for i in issues[:50]:
            lines.append(f"  {i['account_id']} {i['region']:<15} {i['status']:<16} {_short(i['error'], 100)}")
        if len(issues) > 50:
            lines.append(f"  ... and {len(issues) - 50} more (see the regions CSV)")
    if summary["notes"]:
        lines += ["", "NOTES", "-" * 72]
        lines += [f"  {_short(n, 160)}" for n in summary["notes"][:50]]

    u = summary["api_usage"]
    lines += ["", "API USAGE", "-" * 72,
              f"  GetMetricData calls: {u['get_metric_data_calls']:,}   metrics requested: "
              f"{u['metrics_requested']:,}   estimated cost: ${u['estimated_cost_usd']:.2f}   "
              f"throttle retries: {u['throttle_retries']:,}"]
    if summary.get("interrupted"):
        lines += ["", "!! Run was interrupted: results are incomplete."]
    lines += ["=" * 72]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------

def atomic_write(path: str, write: Callable[[Any], None]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
            write(f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


LOG_GROUP_FIELDS = [
    "account_id", "account_name", "region", "log_group", "category", "log_group_class", "shippable",
    "shippable_reason", "subscription_filters", "subscription_destinations", "subscription_status",
    "total_bytes", "total_events", "avg_gb_per_day", "peak_gb_per_day", "avg_events_per_day",
    "peak_events_per_day", "avg_event_bytes", "metric_status",
]
REGION_FIELDS = [
    "account_id", "account_name", "region", "auth", "status", "error", "log_groups", "active_log_groups",
    "account_level_bytes", "account_level_events", "log_group_sum_bytes", "log_group_sum_events", "gap_pct",
    "avg_gb_per_day", "avg_events_per_day",
]


def write_log_groups_csv(path: str, results: Sequence[RegionResult], window: Window, namer: Namer) -> None:
    def write(f) -> None:
        w = csv.DictWriter(f, fieldnames=LOG_GROUP_FIELDS)
        w.writeheader()
        for r in sorted(results, key=lambda x: (x.account_id, x.region)):
            for g in sorted(r.log_groups, key=lambda x: -x.bytes_total):
                collected = r.metrics_done
                w.writerow({
                    "account_id": r.account_id, "account_name": r.account_name, "region": r.region,
                    "log_group": namer.log_group(g.name), "category": g.category,
                    "log_group_class": g.log_class, "shippable": "yes" if g.shippable else "no",
                    "shippable_reason": g.shippable_reason,
                    "subscription_filters": "" if g.subscription_filters is None else g.subscription_filters,
                    "subscription_destinations": namer.destinations(g.subscription_destinations),
                    "subscription_status": g.subscription_status,
                    "total_bytes": int(g.bytes_total) if collected else "",
                    "total_events": int(g.events_total) if collected else "",
                    "avg_gb_per_day": f"{gb(g.bytes_total) / window.days:.6f}" if collected else "",
                    "peak_gb_per_day": f"{gb(max(g.bytes_daily or [0.0])):.6f}" if collected else "",
                    "avg_events_per_day": round(g.events_total / window.days) if collected else "",
                    "peak_events_per_day": int(max(g.events_daily or [0.0])) if collected else "",
                    "avg_event_bytes": round(g.bytes_total / g.events_total) if collected and g.events_total else "",
                    "metric_status": g.metric_status if collected else r.status,
                })
    atomic_write(path, write)


def write_regions_csv(path: str, results: Sequence[RegionResult], window: Window) -> None:
    def write(f) -> None:
        w = csv.DictWriter(f, fieldnames=REGION_FIELDS)
        w.writeheader()
        for r in sorted(results, key=lambda x: (x.account_id, x.region)):
            done = r.metrics_done
            gap = ""
            if done and r.total_bytes > 0:
                gap = f"{100.0 * (r.total_bytes - r.group_bytes) / r.total_bytes:.2f}"
            w.writerow({
                "account_id": r.account_id, "account_name": r.account_name, "region": r.region,
                "auth": r.auth, "status": r.status, "error": r.error,
                "log_groups": len(r.log_groups) if r.inventory_done else "",
                "active_log_groups": sum(1 for g in r.log_groups if g.active) if done else "",
                "account_level_bytes": int(r.total_bytes) if done else "",
                "account_level_events": int(r.total_events) if done else "",
                "log_group_sum_bytes": int(r.group_bytes) if done else "",
                "log_group_sum_events": int(r.group_events) if done else "",
                "gap_pct": gap,
                "avg_gb_per_day": f"{gb(r.total_bytes) / window.days:.6f}" if done else "",
                "avg_events_per_day": round(r.total_events / window.days) if done else "",
            })
    atomic_write(path, write)


def write_outputs(prefix: str, results: Sequence[RegionResult], accounts: Sequence[Account], window: Window,
                  meta: dict, args: argparse.Namespace) -> Tuple[dict, List[str]]:
    namer = Namer(args.redact)
    paths = {
        "log_groups": f"{prefix}_log_groups.csv",
        "regions": f"{prefix}_regions.csv",
        "summary_txt": f"{prefix}_summary.txt",
        "summary_json": f"{prefix}_summary.json",
    }
    summary = build_summary(results, accounts, window, meta, namer, args.check_subscriptions)
    summary["output_files"] = list(paths.values())
    write_log_groups_csv(paths["log_groups"], results, window, namer)
    write_regions_csv(paths["regions"], results, window)
    text = render_text(summary)
    atomic_write(paths["summary_txt"], lambda f: f.write(text + "\n"))
    atomic_write(paths["summary_json"], lambda f: json.dump(summary, f, indent=2))
    return summary, list(paths.values())


def exit_code_for(results: Sequence[RegionResult], interrupted: bool) -> int:
    if interrupted:
        return 130
    if not any(r.metrics_done for r in results):
        return 1
    if any(r.status in FAILURE_STATUSES for r in results):
        return 2
    return 0


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def run_preflight(mode: str, accounts: List[Account], caller: Optional[Caller], args: argparse.Namespace) -> int:
    """Check every permission the scan needs in one account and region; in role mode, also
    check that the role can be assumed in every account. Exit 0 = ok, 2 = some accounts
    unreachable, 1 = a required permission failed."""
    if not accounts:
        print("Preflight: no accounts to check.")
        return 1
    rows: List[Tuple[str, bool, str, str]] = []
    unreachable: List[Tuple[Account, str]] = []

    if caller:
        rows.append(("sts:GetCallerIdentity", True, "PASS", caller.arn))

    if mode == "role":
        assert caller is not None
        lock = threading.Lock()

        def try_assume(a: Account) -> None:
            try:
                a.credentials = role_credentials(caller, a.id, args.role_name)
                a.auth = f"role:{args.role_name}"
            except Exception as e:
                if a.id == caller.account_id:
                    a.credentials = caller.credentials
                    a.auth = "caller_credentials"
                    a.notes.append(classify_error(e)[1])
                else:
                    with lock:
                        unreachable.append((a, classify_error(e)[1]))

        print(f"Checking sts:AssumeRole into {len(accounts)} account(s)...")
        run_parallel(accounts, try_assume, args.workers, "assume-role", lambda a, e: None)
        members = [a for a in accounts if a.id != caller.account_id]
        ok_members = [a for a in members if a.credentials is not None]
        if members and not ok_members:
            rows.append(("sts:AssumeRole", True, "FAIL", f"0/{len(members)} member accounts: {unreachable[0][1]}"))
        elif unreachable:
            rows.append(("sts:AssumeRole", True, "WARN",
                         f"{len(ok_members)}/{len(members)} member accounts; see the list below"))
        elif members:
            rows.append(("sts:AssumeRole", True, "PASS", f"{len(ok_members)}/{len(members)} member accounts"))
        own = [a for a in accounts if a.id == caller.account_id and a.auth == "caller_credentials"]
        if own:
            rows.append(("(own account)", False, "INFO",
                         f"{own[0].id}: role not assumable; the scan uses the caller's own credentials"))
        candidates = ok_members or [a for a in accounts if a.credentials is not None]
    else:
        candidates = [a for a in accounts if a.credentials is not None]
        for a in accounts:
            if a.credentials is None:
                rows.append(("credentials", True, "FAIL", f"{a.name}: {a.error}"))

    acct = candidates[0] if candidates else None
    if acct is not None:
        region = (args.regions or [acct.default_region or acct.home_region])[0]
        print(f"Checking permissions in account {acct.id} ({acct.name}), region {region}...")

        def check(action: str, required: bool, fn: Callable[[], str]) -> None:
            try:
                rows.append((action, required, "PASS", fn()))
            except Exception as e:
                status, msg = classify_error(e, acct.profile)
                rows.append((action, required, "FAIL" if required else "WARN", f"{status}: {msg}"))

        def client(service: str, in_region: str):
            return make_client(new_session(acct.credentials, in_region, acct.profile), service, in_region)

        sample: Dict[str, str] = {}

        def regions() -> str:
            return f"{len(client('ec2', acct.home_region).describe_regions(AllRegions=False)['Regions'])} enabled regions"

        def log_groups() -> str:
            groups = client("logs", region).describe_log_groups(limit=1).get("logGroups", [])
            if groups:
                sample["name"] = groups[0]["logGroupName"]
            return f"{region}: ok"

        def metrics() -> str:
            w = compute_window(1)
            resp = client("cloudwatch", region).get_metric_data(
                MetricDataQueries=[metric_query("tb", "IncomingBytes", None)], StartTime=w.start, EndTime=w.end,
            )
            USAGE.add_gmd(1)
            results = resp.get("MetricDataResults") or [{}]
            st = results[0].get("StatusCode", "Complete")
            if st == "Forbidden":
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "StatusCode Forbidden"}},
                                  "GetMetricData")
            return f"{region}: {st}"

        def alias() -> str:
            aliases = client("iam", acct.home_region).list_account_aliases().get("AccountAliases", [])
            return aliases[0] if aliases else "(no alias)"

        def subscriptions() -> str:
            name = sample.get("name", "/coralogix/preflight-nonexistent")
            try:
                client("logs", region).describe_subscription_filters(logGroupName=name, limit=1)
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
            return f"{region}: ok"

        check("ec2:DescribeRegions", True, regions)
        check("logs:DescribeLogGroups", True, log_groups)
        check("cloudwatch:GetMetricData", True, metrics)
        check("iam:ListAccountAliases", False, alias)
        check("logs:DescribeSubscriptionFilters", bool(args.check_subscriptions), subscriptions)

    width = max(len(r[0]) for r in rows) + 2
    print()
    print(f"  {'Permission':<{width}} {'Required':<9} {'Result':<7} Detail")
    print(f"  {'-' * (width - 1)} {'-' * 8} {'-' * 6} {'-' * 40}")
    for action, required, result, detail in rows:
        print(f"  {action:<{width}} {'yes' if required else 'no':<9} {result:<7} {_short(detail, 120)}")

    if unreachable:
        print(f"\n  {len(unreachable)} account(s) cannot be scanned (role missing, not trusted, or blocked):")
        for a, msg in sorted(unreachable, key=lambda x: x[0].id)[:20]:
            print(f"    {a.id} ({a.name}): {_short(msg, 110)}")
        if len(unreachable) > 20:
            print(f"    ... and {len(unreachable) - 20} more")

    print()
    if any(r[2] == "FAIL" for r in rows):
        print("Preflight FAILED: fix the required permissions above.")
        return 1
    if unreachable:
        print("Preflight passed for reachable accounts; the accounts listed above will be skipped.")
        return 2
    print("Preflight passed.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    p = _ArgumentParser(
        description="Measure CloudWatch Logs ingested bytes and event counts for Coralogix sizing (read-only).",
    )
    auth = p.add_argument_group("accounts (default: the account behind your current credentials)")
    auth.add_argument("--profiles", nargs="+", metavar="PROFILE",
                      help="AWS CLI profiles to scan, one account each.")
    auth.add_argument("--role-name", metavar="NAME",
                      help="Role to assume in each account (e.g. CoralogixLogSizingRole).")
    auth.add_argument("--accounts-file", metavar="PATH",
                      help='JSON list of accounts: [{"id": "123456789012", "name": "prod"}]. With --role-name, '
                           "accounts are scanned via the role; without it, each entry needs a \"profile\". "
                           "If omitted with --role-name, accounts are listed from AWS Organizations.")
    p.add_argument("--regions", nargs="+", metavar="REGION",
                   help="Regions to scan. Default: every enabled region in each account.")
    p.add_argument("--lookback-days", type=int, default=30,
                   help=f"Complete UTC days to measure, 1-{MAX_LOOKBACK_DAYS} (default 30).")
    p.add_argument("--workers", type=int, default=10, help=f"Parallel account-region tasks, 1-{MAX_WORKERS} (default 10).")
    p.add_argument("--output", default="log_sizing", help="Output file prefix (default log_sizing).")
    p.add_argument("--check-subscriptions", action="store_true",
                   help="Also count existing subscription filters on active Standard log groups "
                        "(one API call per log group; needs logs:DescribeSubscriptionFilters).")
    p.add_argument("--redact", action="store_true",
                   help="Replace log group names with stable hashes (prefix kept) in all outputs.")
    p.add_argument("--preflight", action="store_true",
                   help="Check permissions in the first account and region, print a table, and exit.")
    p.add_argument("--yes", action="store_true", help="Do not ask for confirmation before the metrics phase.")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    args = p.parse_args(argv)

    if args.profiles and (args.role_name or args.accounts_file):
        p.error("--profiles cannot be combined with --role-name or --accounts-file")
    if not 1 <= args.lookback_days <= MAX_LOOKBACK_DAYS:
        p.error(f"--lookback-days must be between 1 and {MAX_LOOKBACK_DAYS}")
    if not 1 <= args.workers <= MAX_WORKERS:
        p.error(f"--workers must be between 1 and {MAX_WORKERS}")
    if args.regions:
        bad = [r for r in args.regions if not REGION_RE.match(r)]
        if bad:
            p.error(f"invalid region name(s): {', '.join(bad)}")
        args.regions = list(dict.fromkeys(args.regions))
    if args.role_name and not re.match(r"^[\w+=,.@/-]{1,64}$", args.role_name):
        p.error(f"invalid --role-name: {args.role_name!r}")
    return args


def check_boto3_version() -> None:
    parts = re.findall(r"\d+", boto3.__version__)[:2]
    version = tuple(int(x) for x in parts) if len(parts) == 2 else (0, 0)
    if version < MIN_BOTO3:
        raise UsageError(
            f"boto3 {boto3.__version__} is too old (need >= {MIN_BOTO3[0]}.{MIN_BOTO3[1]} to read log group classes). "
            "Upgrade with: pip install --upgrade boto3"
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        check_boto3_version()
        mode, accounts, caller = resolve_accounts(args)
    except UsageError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: could not resolve AWS credentials: {classify_error(e)[1]}", file=sys.stderr)
        return 1

    if not accounts:
        print("ERROR: no accounts to scan.", file=sys.stderr)
        return 1
    if caller:
        print(f"Caller: {caller.arn}")
    print(f"Mode: {mode}   Accounts: {len(accounts)}   Lookback: {args.lookback_days} days")

    if args.preflight:
        return run_preflight(mode, accounts, caller, args)

    window = compute_window(args.lookback_days)
    meta = {
        "tool_version": TOOL_VERSION,
        "mode": mode,
        "caller_arn": (redact_arn(caller.arn) if args.redact else caller.arn) if caller else None,
        "regions_requested": args.regions,
        "redacted": bool(args.redact),
        "check_subscriptions": bool(args.check_subscriptions),
        "python": "%d.%d.%d" % sys.version_info[:3],
        "boto3": boto3.__version__,
        "interrupted": False,
    }
    results: List[RegionResult] = []
    interrupted = False

    try:
        def prep_error(acct: Account, e: BaseException) -> None:
            acct.status, acct.error = classify_error(e, acct.profile)

        print("\nPhase 1/3: authenticating and discovering enabled regions...")
        run_parallel(accounts, lambda a: prepare_account(a, mode, caller, args), args.workers, "accounts", prep_error)

        acct_by_id: Dict[str, Account] = {}
        tasks: List[Tuple[Account, RegionResult]] = []
        for acct in accounts:
            if not acct.ready:
                results.append(RegionResult(account_id=acct.id, account_name=acct.name, region="-",
                                            auth=acct.auth, status=acct.status, error=acct.error))
                print(f"  SKIP {acct.id} ({acct.name}): {acct.status}: {acct.error}")
                continue
            acct_by_id[acct.id] = acct
            for region in acct.disabled_regions:
                results.append(RegionResult(account_id=acct.id, account_name=acct.name, region=region,
                                            auth=acct.auth, status=STATUS_REGION_DISABLED,
                                            error="region is not enabled for this account"))
            for region in acct.regions:
                rr = RegionResult(account_id=acct.id, account_name=acct.name, region=region, auth=acct.auth)
                results.append(rr)
                tasks.append((acct, rr))
            for note in acct.notes:
                print(f"  Note {acct.id}: {note}")

        if not tasks:
            print("\nERROR: no account-region pairs could be scanned.", file=sys.stderr)
            summary, files = write_outputs(args.output, results, accounts, window, meta, args)
            print(render_text(summary))
            return 1

        def task_error(item: Tuple[Account, RegionResult], e: BaseException) -> None:
            acct, rr = item
            rr.fail(*classify_error(e, acct.profile))

        print(f"\nPhase 2/3: listing log groups in {len(tasks)} account-region pair(s)...")
        run_parallel(tasks, lambda t: collect_inventory(*t), args.workers, "inventory", task_error)

        metric_tasks = [(a, rr) for a, rr in tasks if rr.inventory_done]
        n_groups = sum(len(rr.log_groups) for _, rr in metric_tasks)
        n_metrics = 2 * n_groups + 2 * len(metric_tasks)
        n_calls = sum(math.ceil((2 * len(rr.log_groups) + 2) / MAX_QUERIES_PER_CALL) for _, rr in metric_tasks)
        est_cost = n_metrics / 1000.0 * GMD_USD_PER_1000_METRICS
        failed_inv = len(tasks) - len(metric_tasks)
        print(f"\n  Found {n_groups:,} log groups in {len(metric_tasks)} account-region pair(s)"
              + (f" ({failed_inv} pair(s) could not be listed)" if failed_inv else ""))
        print(f"  GetMetricData: ~{n_metrics:,} metrics in ~{n_calls:,} call(s), "
              f"estimated cost ${est_cost:.2f} (at ${GMD_USD_PER_1000_METRICS} per 1,000 metrics)")

        if est_cost > CONFIRM_COST_THRESHOLD_USD and not args.yes and sys.stdin.isatty():
            answer = input("  Continue? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("Aborted before the metrics phase. No metrics were requested.")
                return 1

        print(f"\nPhase 3/3: reading {args.lookback_days} days of ingestion metrics...")
        run_parallel(metric_tasks, lambda t: collect_metrics(t[0], t[1], window), args.workers, "metrics", task_error)

        if args.check_subscriptions:
            sub_tasks = [(a, rr) for a, rr in metric_tasks if rr.metrics_done]
            n_sub = sum(1 for _, rr in sub_tasks for g in rr.log_groups if g.active and g.log_class == "STANDARD")
            print(f"\nChecking subscription filters on {n_sub:,} active Standard log group(s)...")

            def sub_error(item: Tuple[Account, RegionResult], e: BaseException) -> None:
                item[1].notes.append(f"subscription check failed: {classify_error(e, item[0].profile)[1]}")

            run_parallel(sub_tasks, lambda t: collect_subscriptions(*t), args.workers, "subscriptions", sub_error)
    except KeyboardInterrupt:
        interrupted = True
        meta["interrupted"] = True
        print("\nInterrupted: writing partial results...", file=sys.stderr)
        for rr in results:
            if rr.status == STATUS_NOT_RUN and not rr.error:
                rr.error = "run interrupted before this region was measured"

    summary, files = write_outputs(args.output, results, accounts, window, meta, args)
    print()
    print(render_text(summary))
    print("\nOutput files:")
    for path in files:
        print(f"  {path}")
    code = exit_code_for(results, interrupted)
    if code == 2:
        print("\nFinished with some accounts or regions not fully scanned (exit code 2); see NOT FULLY SCANNED.")
    if interrupted:
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    return code


if __name__ == "__main__":
    sys.exit(main())
