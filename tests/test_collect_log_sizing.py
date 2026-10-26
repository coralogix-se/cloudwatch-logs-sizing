from __future__ import annotations

import json
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import collect_log_sizing as cls  # noqa: E402


WINDOW = cls.compute_window(3, now=datetime(2026, 10, 26, 15, 30, tzinfo=timezone.utc))


def client(service: str):
    return boto3.client(service, region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")


def client_error(code: str, message: str = "", op: str = "DescribeLogGroups") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, op)


def group(name: str, log_class: str = "STANDARD", bytes_daily=None, events_daily=None) -> cls.LogGroup:
    category, _ = cls.categorize(name)
    ok, reason = cls.shippability(log_class)
    return cls.LogGroup(name=name, log_class=log_class, category=category, shippable=ok, shippable_reason=reason,
                        bytes_daily=list(bytes_daily or []), events_daily=list(events_daily or []),
                        metric_status=cls.STATUS_OK)


def utc(y, m, d) -> datetime:
    return datetime(y, m, d, tzinfo=timezone.utc)


class FakeCloudWatch:
    """Scripted GetMetricData: `pages` is a list of responses, or a callable(queries, call_no)."""

    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def get_metric_data(self, **kwargs):
        self.calls.append(kwargs)
        return self.respond(kwargs, len(self.calls) - 1)


def complete_for(queries, value=1.0, day=None):
    day = day or WINDOW.start
    return {
        "MetricDataResults": [
            {"Id": q["Id"], "Timestamps": [day], "Values": [value], "StatusCode": "Complete"} for q in queries
        ]
    }


@pytest.fixture(autouse=True)
def reset_usage():
    cls.USAGE.__init__()
    yield


# ---------------------------------------------------------------------------
# Window and timestamps
# ---------------------------------------------------------------------------

def test_window_is_complete_utc_days():
    assert WINDOW.end == utc(2026, 10, 26)
    assert WINDOW.start == utc(2026, 10, 23)
    assert WINDOW.dates == [date(2026, 10, 23), date(2026, 10, 24), date(2026, 10, 25)]


def test_window_from_non_utc_now():
    now = datetime(2026, 10, 26, 0, 30, tzinfo=timezone(timedelta(hours=2)))  # 2026-10-25 22:30 UTC
    w = cls.compute_window(1, now=now)
    assert w.end == utc(2026, 10, 25)
    assert w.dates == [date(2026, 10, 24)]


@pytest.mark.skipif(not hasattr(time, "tzset"), reason="tzset not available")
def test_local_timezone_timestamps_map_to_utc_days(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    time.tzset()
    try:
        bst = timezone(timedelta(hours=1))
        # botocore returns local-time timestamps: midnight UTC arrives as 01:00+01:00
        local_ts = [datetime(2026, 10, 23, 1, 0, tzinfo=bst), datetime(2026, 10, 24, 1, 0, tzinfo=bst)]

        def respond(kwargs, n):
            return {"MetricDataResults": [
                {"Id": "tb", "Timestamps": local_ts, "Values": [10.0, 20.0], "StatusCode": "Complete"}]}

        series, status, _ = cls.run_get_metric_data(FakeCloudWatch(respond), [cls.metric_query("tb", "IncomingBytes", None)], WINDOW)
        assert cls.to_daily(series["tb"], WINDOW) == [10.0, 20.0, 0.0]
    finally:
        monkeypatch.delenv("TZ")
        time.tzset()


# ---------------------------------------------------------------------------
# GetMetricData batching, paging, status codes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n_groups, expected_calls", [(249, 1), (250, 2), (251, 2), (500, 3)])
def test_batching_boundary(n_groups, expected_calls):
    groups = [group(f"/g/{i}") for i in range(n_groups)]
    queries = cls.build_queries(groups)
    assert len(queries) == 2 * n_groups + 2
    cw = FakeCloudWatch(lambda kwargs, n: complete_for(kwargs["MetricDataQueries"]))
    series, status, _ = cls.fetch_metrics(cw, queries, WINDOW, sleep=lambda s: None)
    assert len(cw.calls) == expected_calls
    assert all(len(c["MetricDataQueries"]) <= cls.MAX_QUERIES_PER_CALL for c in cw.calls)
    assert set(series) == {q["Id"] for q in queries}
    assert all(s == "Complete" for s in status.values())
    assert cls.USAGE.gmd_metrics == len(queries)


def test_query_ids_are_valid_and_map_back():
    groups = [group("/aws/lambda/a"), group("weird name #1")]
    queries = cls.build_queries(groups)
    ids = [q["Id"] for q in queries]
    assert ids == ["tb", "te", "b0", "e0", "b1", "e1"]
    assert all(cls.re.match(r"^[a-z][a-zA-Z0-9_]*$", i) for i in ids)
    assert queries[4]["MetricStat"]["Metric"]["Dimensions"] == [{"Name": "LogGroupName", "Value": "weird name #1"}]
    assert queries[0]["MetricStat"]["Metric"]["Dimensions"] == []
    assert queries[0]["MetricStat"]["Period"] == 86400 and queries[0]["MetricStat"]["Stat"] == "Sum"


def test_next_token_merges_query_split_across_pages():
    pages = [
        {"MetricDataResults": [{"Id": "tb", "Timestamps": [utc(2026, 10, 23)], "Values": [5.0],
                                "StatusCode": "PartialData"}], "NextToken": "t1"},
        {"MetricDataResults": [{"Id": "tb", "Timestamps": [utc(2026, 10, 24), utc(2026, 10, 25)],
                                "Values": [6.0, 7.0], "StatusCode": "Complete"}]},
    ]
    cw = FakeCloudWatch(lambda kwargs, n: pages[n])
    series, status, _ = cls.run_get_metric_data(cw, [cls.metric_query("tb", "IncomingBytes", None)], WINDOW)
    assert cw.calls[1]["NextToken"] == "t1"
    assert cls.to_daily(series["tb"], WINDOW) == [5.0, 6.0, 7.0]
    assert status["tb"] == "Complete"
    assert cls.USAGE.gmd_calls == 2


def test_partial_data_on_earlier_page_only_is_complete():
    pages = [
        {"MetricDataResults": [{"Id": "tb", "Timestamps": [], "Values": [], "StatusCode": "PartialData"},
                               {"Id": "te", "Timestamps": [], "Values": [], "StatusCode": "Complete"}],
         "NextToken": "t1"},
        {"MetricDataResults": [{"Id": "te", "Timestamps": [], "Values": [], "StatusCode": "Complete"}]},
    ]
    cw = FakeCloudWatch(lambda kwargs, n: pages[n])
    queries = [cls.metric_query("tb", "IncomingBytes", None), cls.metric_query("te", "IncomingLogEvents", None)]
    _, status, _ = cls.run_get_metric_data(cw, queries, WINDOW)
    assert status == {"tb": "Complete", "te": "Complete"}


def test_partial_and_internal_error_are_retried_then_flagged():
    def respond(kwargs, n):
        out = []
        for q in kwargs["MetricDataQueries"]:
            st = "Complete"
            if q["Id"] == "b0":
                st = "InternalError" if n == 0 else "Complete"
            if q["Id"] == "e0":
                st = "PartialData"
            out.append({"Id": q["Id"], "Timestamps": [WINDOW.start], "Values": [1.0], "StatusCode": st})
        return {"MetricDataResults": out}

    sleeps = []
    cw = FakeCloudWatch(respond)
    queries = cls.build_queries([group("/g")])
    _, status, _ = cls.fetch_metrics(cw, queries, WINDOW, sleep=sleeps.append)
    assert status["b0"] == "Complete"
    assert status["e0"] == "PartialData"
    assert len(cw.calls) == cls.GMD_RETRY_ATTEMPTS
    assert [q["Id"] for q in cw.calls[1]["MetricDataQueries"]] == ["b0", "e0"]
    assert [q["Id"] for q in cw.calls[2]["MetricDataQueries"]] == ["e0"]
    assert sleeps == [1, 2]


def _region_with_cw(monkeypatch, respond, groups):
    cw = FakeCloudWatch(respond)
    monkeypatch.setattr(cls, "make_client", lambda session, service, region, endpoint_url=None: cw)
    monkeypatch.setattr(cls, "new_session", lambda *a, **k: None)
    monkeypatch.setattr(cls.time, "sleep", lambda s: None)
    acct = cls.Account(id="111111111111", name="a")
    rr = cls.RegionResult(account_id=acct.id, account_name="a", region="us-east-1",
                          inventory_done=True, log_groups=groups)
    return acct, rr


def test_collect_metrics_partial_status(monkeypatch):
    def respond(kwargs, n):
        return {"MetricDataResults": [
            {"Id": q["Id"], "Timestamps": [WINDOW.start], "Values": [2.0],
             "StatusCode": "PartialData" if q["Id"] == "b1" else "Complete"} for q in kwargs["MetricDataQueries"]]}

    acct, rr = _region_with_cw(monkeypatch, respond, [group("/a"), group("/b")])
    cls.collect_metrics(acct, rr, WINDOW)
    assert rr.metrics_done
    assert rr.status == cls.STATUS_PARTIAL
    assert [g.metric_status for g in rr.log_groups] == [cls.STATUS_OK, cls.STATUS_PARTIAL]
    assert rr.account_bytes_daily == [2.0, 0.0, 0.0]


def test_collect_metrics_complete_sets_ok(monkeypatch):
    acct, rr = _region_with_cw(monkeypatch, lambda kw, n: complete_for(kw["MetricDataQueries"]), [group("/a")])
    assert rr.status == cls.STATUS_NOT_RUN
    cls.collect_metrics(acct, rr, WINDOW)
    assert rr.metrics_done and rr.status == cls.STATUS_OK


def test_collect_metrics_forbidden_is_access_denied_not_zero(monkeypatch):
    def respond(kwargs, n):
        return {"MetricDataResults": [
            {"Id": q["Id"], "Timestamps": [], "Values": [], "StatusCode": "Forbidden"}
            for q in kwargs["MetricDataQueries"]]}

    acct, rr = _region_with_cw(monkeypatch, respond, [group("/a")])
    cls.collect_metrics(acct, rr, WINDOW)
    assert rr.status == cls.STATUS_ACCESS_DENIED
    assert not rr.metrics_done
    assert rr.account_bytes_daily is None


def test_collect_metrics_client_error(monkeypatch):
    def respond(kwargs, n):
        raise client_error("AccessDenied", "not authorized", op="GetMetricData")

    acct, rr = _region_with_cw(monkeypatch, respond, [])
    cls.collect_metrics(acct, rr, WINDOW)
    assert rr.status == cls.STATUS_ACCESS_DENIED
    assert "GetMetricData" in rr.error


# ---------------------------------------------------------------------------
# Inventory, regions and error classification (botocore Stubber)
# ---------------------------------------------------------------------------

def _stub_clients(monkeypatch, clients):
    monkeypatch.setattr(cls, "make_client", lambda session, service, region, endpoint_url=None: clients[service])
    monkeypatch.setattr(cls, "new_session", lambda *a, **k: None)


def test_inventory_paginates_and_sets_shippable(monkeypatch):
    logs = client("logs")
    stub = Stubber(logs)
    stub.add_response("describe_log_groups", {
        "logGroups": [{"logGroupName": "/aws/lambda/f", "logGroupClass": "STANDARD"},
                      {"logGroupName": "archive", "logGroupClass": "INFREQUENT_ACCESS"}],
        "nextToken": "n1"}, {"limit": 50})
    stub.add_response("describe_log_groups", {
        "logGroups": [{"logGroupName": "/aws/vendedlogs/x", "logGroupClass": "DELIVERY"},
                      {"logGroupName": "legacy"}]}, {"limit": 50, "nextToken": "n1"})
    _stub_clients(monkeypatch, {"logs": logs})
    acct = cls.Account(id="111111111111", name="a")
    rr = cls.RegionResult(account_id=acct.id, account_name="a", region="us-east-1")
    with stub:
        cls.collect_inventory(acct, rr)
    # A region is only "ok" once its metrics are collected (an interrupted run must not report it as ok).
    assert rr.inventory_done and rr.status == cls.STATUS_NOT_RUN
    assert [(g.name, g.log_class, g.shippable) for g in rr.log_groups] == [
        ("/aws/lambda/f", "STANDARD", True),
        ("archive", "INFREQUENT_ACCESS", False),
        ("/aws/vendedlogs/x", "DELIVERY", False),
        ("legacy", "STANDARD", True),
    ]
    assert rr.log_groups[0].category == "Lambda"


@pytest.mark.parametrize("code, message, expected", [
    ("AccessDeniedException", "User is not authorized", cls.STATUS_ACCESS_DENIED),
    ("AccessDeniedException", "... with an explicit deny in a service control policy", cls.STATUS_SCP_DENIED),
    ("ThrottlingException", "Rate exceeded", cls.STATUS_THROTTLED),
    ("InternalFailure", "boom", cls.STATUS_ERROR),
])
def test_inventory_failure_is_a_status_not_zero(monkeypatch, code, message, expected):
    logs = client("logs")
    stub = Stubber(logs)
    stub.add_client_error("describe_log_groups", service_error_code=code, service_message=message)
    _stub_clients(monkeypatch, {"logs": logs})
    acct = cls.Account(id="111111111111", name="a")
    rr = cls.RegionResult(account_id=acct.id, account_name="a", region="us-east-1")
    with stub:
        cls.collect_inventory(acct, rr)
    assert rr.status == expected
    assert not rr.inventory_done and rr.log_groups == []


def test_token_rejected_in_fallback_region_list_is_region_disabled(monkeypatch):
    logs = client("logs")
    stub = Stubber(logs)
    stub.add_client_error("describe_log_groups", service_error_code="UnrecognizedClientException",
                          service_message="The security token included in the request is invalid")
    _stub_clients(monkeypatch, {"logs": logs})
    acct = cls.Account(id="111111111111", name="a", region_source="fallback")
    rr = cls.RegionResult(account_id=acct.id, account_name="a", region="me-central-1")
    with stub:
        cls.collect_inventory(acct, rr)
    assert rr.status == cls.STATUS_REGION_DISABLED


def test_requested_disabled_regions_are_reported(monkeypatch):
    ec2 = client("ec2")
    stub = Stubber(ec2)
    stub.add_response("describe_regions", {"Regions": [
        {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
        {"RegionName": "eu-south-1", "OptInStatus": "opted-in"},
    ]}, {"AllRegions": False})
    _stub_clients(monkeypatch, {"ec2": ec2})
    acct = cls.Account(id="111111111111", name="a")
    with stub:
        cls.discover_regions(acct, ["us-east-1", "me-central-1"])
    assert acct.regions == ["us-east-1"]
    assert acct.disabled_regions == ["me-central-1"]
    assert acct.region_source == "describe_regions"


def test_describe_regions_failure_falls_back_with_note(monkeypatch):
    ec2 = client("ec2")
    stub = Stubber(ec2)
    stub.add_client_error("describe_regions", service_error_code="UnauthorizedOperation", service_message="no")
    _stub_clients(monkeypatch, {"ec2": ec2})
    acct = cls.Account(id="111111111111", name="a")
    with stub:
        cls.discover_regions(acct, None)
    assert acct.region_source == "fallback"
    assert "us-east-1" in acct.regions
    assert acct.notes and "DescribeRegions" in acct.notes[0]


def test_classify_sso_and_misc_errors():
    sso_errors = cls.SSO_ERRORS
    if sso_errors:
        err = sso_errors[0].__new__(sso_errors[0])
        Exception.__init__(err, "expired")
        status, msg = cls.classify_error(err, profile="prod")
        assert status == cls.STATUS_ERROR and "aws sso login --profile prod" in msg
    status, msg = cls.classify_error(cls.NoCredentialsError())
    assert status == cls.STATUS_ERROR and "credentials" in msg.lower()
    status, msg = cls.classify_error(client_error("ExpiredToken", "expired", op="GetMetricData"))
    assert status == cls.STATUS_ERROR and "rejected" in msg


def test_role_assume_failure_in_own_account_falls_back(monkeypatch):
    caller = cls.Caller(account_id="111111111111", arn="arn:aws:iam::111111111111:user/u", partition="aws",
                        home_region="us-east-1", default_region=None, credentials="CALLER")

    def boom(*a, **k):
        raise client_error("AccessDenied", "nope", op="AssumeRole")

    monkeypatch.setattr(cls, "role_credentials", boom)
    monkeypatch.setattr(cls, "discover_regions", lambda acct, requested: setattr(acct, "regions", ["us-east-1"]))
    monkeypatch.setattr(cls, "account_alias", lambda acct: None)
    args = cls.parse_args(["--role-name", "R"])
    own = cls.prepare_account(cls.Account(id="111111111111", name="111111111111"), "role", caller, args)
    other = cls.prepare_account(cls.Account(id="222222222222", name="b"), "role", caller, args)
    assert own.ready and own.credentials == "CALLER" and own.auth == "caller_credentials"
    assert not other.ready and other.status == cls.STATUS_ACCESS_DENIED
    assert "Could not assume role R" in other.error


# ---------------------------------------------------------------------------
# Arguments and accounts file
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("argv", [
    ["--lookback-days", "0"],
    ["--lookback-days", "456"],
    ["--workers", "0"],
    ["--workers", "51"],
    ["--regions", "us-east-1", "not_a_region"],
    ["--profiles", "a", "--role-name", "R"],
    ["--role-name", "bad role name!"],
])
def test_invalid_arguments_exit_1(argv, capsys):
    with pytest.raises(SystemExit) as e:
        cls.parse_args(argv)
    assert e.value.code == 1


def test_valid_arguments_dedupe_regions():
    args = cls.parse_args(["--regions", "us-east-1", "us-east-1", "eu-west-1", "--lookback-days", "455"])
    assert args.regions == ["us-east-1", "eu-west-1"]


@pytest.mark.parametrize("content, fragment", [
    ("not json", "not valid JSON"),
    ("[]", "non-empty JSON list"),
    ('[{"name": "x"}]', '"id"'),
    ('[{"id": 123456789012}]', "quoted string"),
    ('[{"id": "12345"}]', "12-digit"),
])
def test_accounts_file_validation(tmp_path, content, fragment):
    path = tmp_path / "accounts.json"
    path.write_text(content)
    with pytest.raises(cls.UsageError) as e:
        cls.load_accounts_file(str(path))
    assert fragment in str(e.value)


def test_accounts_file_ok_and_deduped(tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps([{"id": "012345678901", "name": "prod"}, {"id": " 012345678901 "},
                                {"id": "111111111111", "profile": "p"}]))
    assert cls.load_accounts_file(str(path)) == [
        {"id": "012345678901", "name": "prod", "profile": None},
        {"id": "111111111111", "name": "111111111111", "profile": "p"},
    ]


def test_accounts_file_without_role_requires_profiles(tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps([{"id": "111111111111"}]))
    with pytest.raises(cls.UsageError) as e:
        cls.resolve_accounts(cls.parse_args(["--accounts-file", str(path)]))
    assert "--role-name" in str(e.value)


# ---------------------------------------------------------------------------
# Summary math, redaction, outputs, exit codes
# ---------------------------------------------------------------------------

def _measured(account_id, region, groups, acct_bytes, acct_events, status=cls.STATUS_OK):
    return cls.RegionResult(account_id=account_id, account_name=f"name-{account_id}", region=region, status=status,
                            inventory_done=True, metrics_done=True, log_groups=groups,
                            account_bytes_daily=acct_bytes, account_events_daily=acct_events)


def _summary(results, redact=False, check_subscriptions=False):
    accounts = [cls.Account(id=i, name=f"name-{i}") for i in sorted({r.account_id for r in results})]
    return cls.build_summary(results, accounts, WINDOW, {"tool_version": "test"}, cls.Namer(redact),
                             check_subscriptions)


def test_summary_math_decimal_gb():
    g1 = group("/aws/lambda/a", bytes_daily=[1e9, 2e9, 3e9], events_daily=[10, 20, 30])
    g2 = group("archive", "INFREQUENT_ACCESS", bytes_daily=[1e9, 0, 0], events_daily=[5, 0, 0])
    r1 = _measured("111111111111", "us-east-1", [g1, g2], [2e9, 2e9, 3e9 + 0.5e9], [15, 20, 30])
    r2 = _measured("222222222222", "eu-west-1", [], [0.0, 1e9, 0.0], [0, 100, 0])
    s = _summary([r1, r2])
    t = s["totals"]
    # Headline = account-level series: (2+0) + (2+1) + (3.5+0) = 8.5 GB over 3 days
    assert t["total_bytes"] == 8_500_000_000
    assert t["avg_gb_per_day"] == round(8.5 / 3, 4)
    assert t["peak_gb_per_day"] == 3.5
    assert t["p95_gb_per_day"] == 3.5
    assert t["monthly_gb"] == 85.0
    assert t["total_events"] == 165
    assert t["avg_events_per_day"] == 55
    assert t["log_group_sum_bytes"] == 7_000_000_000
    sh = s["shippable"]
    assert sh["shippable_gb_per_day"] == 2.0
    assert sh["needs_changes_gb_per_day"] == round(1 / 3, 4)
    assert sh["unattributed_gb_per_day"] == 0.5
    assert sh["by_class_gb_per_day"] == {"INFREQUENT_ACCESS": round(1 / 3, 4), "STANDARD": 2.0}
    assert s["per_account"]["111111111111"]["avg_gb_per_day"] == 2.5
    assert s["per_account"]["111111111111"]["shippable_gb_per_day"] == 2.0
    assert [d["gb"] for d in s["daily_trend"]] == [2.0, 3.0, 3.5]
    assert s["by_category"]["Lambda"]["avg_gb_per_day"] == 2.0
    assert {g["account_id"]: g["gap_pct"] for g in s["log_group_sum_gaps"]} == {
        "111111111111": round(100 * 0.5 / 7.5, 2), "222222222222": 100.0}
    assert s["top_log_groups"][0]["log_group"] == "/aws/lambda/a"


def test_failed_regions_are_excluded_from_totals_and_listed():
    ok = _measured("111111111111", "us-east-1", [], [1e9, 1e9, 1e9], [1, 1, 1])
    denied = cls.RegionResult(account_id="111111111111", account_name="n", region="eu-west-1",
                              status=cls.STATUS_ACCESS_DENIED, error="logs:DescribeLogGroups denied")
    s = _summary([ok, denied])
    assert s["totals"]["avg_gb_per_day"] == 1.0
    assert s["scope"]["status_counts"] == {"ok": 1, "access_denied": 1}
    assert s["issues"][0]["region"] == "eu-west-1"
    assert s["per_account"]["111111111111"]["regions_failed"] == 1


def test_percentile_nearest_rank():
    assert cls.percentile([], 95) == 0.0
    assert cls.percentile([5.0], 95) == 5.0
    assert cls.percentile([float(i) for i in range(1, 21)], 95) == 19.0
    assert cls.percentile([float(i) for i in range(1, 31)], 95) == 29.0


def test_redaction_is_stable_and_keeps_prefix():
    a = cls.redact_name("/aws/lambda/payments-prod")
    assert a.startswith("/aws/lambda/") and "payments" not in a
    assert a == cls.redact_name("/aws/lambda/payments-prod")
    assert len(a) == len("/aws/lambda/") + 12
    assert cls.redact_name("customer-secret-app") != "customer-secret-app"
    namer = cls.Namer(True)
    assert namer.destinations(["arn:aws:lambda:us-east-1:1:function:x", "arn:aws:firehose:us-east-1:1:deliverystream/y"]) == "lambda;firehose"


def test_redact_arn_hides_principal_name():
    r = cls.redact_arn("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/jane@example.com")
    assert r.startswith("arn:aws:sts::123456789012:assumed-role/") and "jane" not in r and "SSO" not in r
    assert "sizing-user" not in cls.redact_arn("arn:aws:iam::123456789012:user/sizing-user")
    assert cls.redact_arn("arn:aws:iam::123456789012:root") == "arn:aws:iam::123456789012:root"


def test_redacted_outputs_contain_no_names(tmp_path):
    g = group("/aws/lambda/secret-service", bytes_daily=[1e9, 1e9, 1e9], events_daily=[1, 1, 1])
    g.subscription_filters = 1
    g.subscription_destinations = ["arn:aws:lambda:us-east-1:111111111111:function:secret-shipper"]
    g.subscription_status = cls.STATUS_OK
    r = _measured("111111111111", "us-east-1", [g], [1e9, 1e9, 1e9], [1, 1, 1])
    args = cls.parse_args(["--redact", "--check-subscriptions", "--output", str(tmp_path / "out")])
    accounts = [cls.Account(id="111111111111", name="n")]
    summary, files = cls.write_outputs(args.output, [r], accounts, WINDOW, {"tool_version": "t"}, args)
    for path in files:
        assert "secret" not in open(path, encoding="utf-8").read(), path
    assert summary["subscriptions"]["with_filters"] == 1
    assert summary["subscriptions"]["destination_types"] == {"lambda": 1}


def test_outputs_written_and_parseable(tmp_path):
    g = group("/aws/eks/c/cluster", bytes_daily=[3e9, 0, 0], events_daily=[3, 0, 0])
    r = _measured("111111111111", "us-east-1", [g], [3e9, 0, 0], [3, 0, 0])
    args = cls.parse_args(["--output", str(tmp_path / "sub" / "out")])
    summary, files = cls.write_outputs(args.output, [r], [cls.Account(id="111111111111", name="n")], WINDOW,
                                       {"tool_version": "t"}, args)
    assert [os.path.basename(f) for f in files] == [
        "out_log_groups.csv", "out_regions.csv", "out_summary.txt", "out_summary.json"]
    data = json.load(open(files[3], encoding="utf-8"))
    assert data["totals"]["avg_gb_per_day"] == 1.0
    lines = open(files[0], encoding="utf-8").read().splitlines()
    assert lines[0].startswith("account_id,account_name,region,log_group")
    assert "/aws/eks/c/cluster" in lines[1]
    assert "CLOUDWATCH LOGS INGESTION SIZING" in open(files[2], encoding="utf-8").read()
    assert not [f for f in os.listdir(tmp_path / "sub") if f.startswith(".tmp_")]


def test_exit_codes():
    ok = _measured("1", "us-east-1", [], [0, 0, 0], [0, 0, 0])
    scp = cls.RegionResult(account_id="1", account_name="n", region="eu-west-1", status=cls.STATUS_SCP_DENIED)
    disabled = cls.RegionResult(account_id="1", account_name="n", region="me-central-1",
                                status=cls.STATUS_REGION_DISABLED)
    denied = cls.RegionResult(account_id="2", account_name="n", region="-", status=cls.STATUS_ACCESS_DENIED)
    assert cls.exit_code_for([ok, scp, disabled], False) == 0
    assert cls.exit_code_for([ok, denied], False) == 2
    assert cls.exit_code_for([denied], False) == 1
    assert cls.exit_code_for([], False) == 1
    assert cls.exit_code_for([ok], True) == 130


def test_categories():
    assert cls.categorize("/aws/lambda/x") == ("Lambda", "/aws/lambda/")
    assert cls.categorize("/aws/containerinsights/c/performance")[0] == "Container Insights"
    assert cls.categorize("API-Gateway-Execution-Logs_abc/prod")[0] == "API Gateway"
    assert cls.categorize("/ecs/svc")[0] == "ECS"
    assert cls.categorize("aws-waf-logs-acl")[0] == "WAF"
    assert cls.categorize("my-app")[0] == "Other"


def test_throttle_counter():
    cls._count_throttles(response=(None, {"Error": {"Code": "ThrottlingException"}}))
    cls._count_throttles(response=(None, {"ResponseMetadata": {}}))
    cls._count_throttles(response=None)
    assert cls.USAGE.throttle_retries == 1


def test_subscription_check(monkeypatch):
    logs = client("logs")
    stub = Stubber(logs)
    stub.add_response("describe_subscription_filters", {"subscriptionFilters": [
        {"filterName": "a", "destinationArn": "arn:aws:lambda:us-east-1:1:function:x"},
        {"filterName": "b", "destinationArn": "arn:aws:firehose:us-east-1:1:deliverystream/y"}]},
        {"logGroupName": "/active"})
    stub.add_client_error("describe_subscription_filters", service_error_code="ResourceNotFoundException",
                          expected_params={"logGroupName": "/deleted"})
    _stub_clients(monkeypatch, {"logs": logs})
    active = group("/active", bytes_daily=[1, 0, 0], events_daily=[1, 0, 0])
    deleted = group("/deleted", bytes_daily=[1, 0, 0], events_daily=[1, 0, 0])
    idle = group("/idle", bytes_daily=[0, 0, 0], events_daily=[0, 0, 0])
    ia = group("/ia", "INFREQUENT_ACCESS", bytes_daily=[1, 0, 0], events_daily=[1, 0, 0])
    rr = _measured("1", "us-east-1", [active, deleted, idle, ia], [4, 0, 0], [4, 0, 0])
    with stub:
        cls.collect_subscriptions(cls.Account(id="1", name="n"), rr)
    stub.assert_no_pending_responses()
    assert active.subscription_filters == 2 and active.subscription_status == cls.STATUS_OK
    assert deleted.subscription_status == "log group no longer exists"
    assert idle.subscription_status == "" and ia.subscription_status == ""
    s = _summary([rr], check_subscriptions=True)
    assert s["subscriptions"]["both_slots_used"] == 1
    assert s["subscriptions"]["destination_types"] == {"lambda": 1, "firehose": 1}
