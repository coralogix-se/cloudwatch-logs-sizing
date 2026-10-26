#!/usr/bin/env python3
"""
Discover AWS accounts accessible to the current user.

Tries three methods in order:
  1. AWS Organizations  — lists all ACTIVE accounts in the org
  2. AWS SSO (Identity Center) — reads cached SSO token, lists SSO-accessible accounts
  3. Named CLI profiles — reads ~/.aws/config, calls STS per profile

Outputs accounts.json ready for collect_log_sizing.py --accounts-file.

Requirements:
    pip install boto3

Usage:
    python discover_accounts.py
    python discover_accounts.py --output accounts.json
    python discover_accounts.py --profiles default prod staging
    python discover_accounts.py --from-profiles
"""

from __future__ import annotations

import argparse
import configparser
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError


# ---------------------------------------------------------------------------
# Method 1 — AWS Organizations
# ---------------------------------------------------------------------------

def try_organizations(session: boto3.Session) -> list[dict] | None:
    """List all ACTIVE accounts via organizations:ListAccounts."""
    try:
        org = session.client("organizations", region_name=session.region_name or "us-east-1")
        paginator = org.get_paginator("list_accounts")
        accounts = []
        for page in paginator.paginate():
            for acct in page["Accounts"]:
                if (acct.get("State") or acct.get("Status")) == "ACTIVE":
                    accounts.append({"id": acct["Id"], "name": acct["Name"]})
        return accounts
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("AccessDeniedException", "AccessDenied", "AWSOrganizationsNotInUseException"):
            return None
        print(f"  Organizations lookup failed: {e}")
        return None
    except (NoCredentialsError, BotoCoreError):
        return None


# ---------------------------------------------------------------------------
# Method 2 — AWS SSO cached token
# ---------------------------------------------------------------------------

def _find_sso_tokens() -> list[dict]:
    """Read non-expired SSO access tokens from ~/.aws/sso/cache/."""
    sso_cache = Path.home() / ".aws" / "sso" / "cache"
    if not sso_cache.is_dir():
        return []

    import datetime
    tokens = []
    for path in sso_cache.glob("*.json"):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        access_token = data.get("accessToken")
        expires_at = data.get("expiresAt")
        region = data.get("region")
        if not access_token or not expires_at:
            continue
        # expiresAt format: 2024-01-15T10:30:00Z (or with +00:00)
        try:
            exp = expires_at.replace("Z", "+00:00")
            expiry = datetime.datetime.fromisoformat(exp)
            if expiry < datetime.datetime.now(datetime.timezone.utc):
                continue
        except (ValueError, TypeError):
            continue
        tokens.append({"accessToken": access_token, "region": region or "us-east-1"})
    return tokens


def _find_sso_region_from_config() -> str | None:
    """Read the sso_region from the first SSO profile in ~/.aws/config."""
    config_path = Path.home() / ".aws" / "config"
    if not config_path.exists():
        return None
    config = configparser.ConfigParser()
    config.read(str(config_path))
    for section in config.sections():
        region = config.get(section, "sso_region", fallback=None)
        if region:
            return region
    return None


def try_sso() -> list[dict] | None:
    """List accounts via SSO using cached tokens."""
    tokens = _find_sso_tokens()
    if not tokens:
        return None

    for token_info in tokens:
        try:
            sso = boto3.client("sso", region_name=token_info["region"])
            accounts = []
            paginator = sso.get_paginator("list_accounts")
            for page in paginator.paginate(accessToken=token_info["accessToken"]):
                for acct in page["accountList"]:
                    accounts.append({
                        "id": acct["accountId"],
                        "name": acct.get("accountName", acct["accountId"]),
                    })
            if accounts:
                return accounts
        except (ClientError, BotoCoreError):
            continue
    return None


# ---------------------------------------------------------------------------
# Method 3 — Named CLI profiles
# ---------------------------------------------------------------------------

def list_config_profiles() -> list[str]:
    """Parse ~/.aws/config and return all profile names."""
    config_path = Path.home() / ".aws" / "config"
    if not config_path.exists():
        return ["default"]
    config = configparser.ConfigParser()
    config.read(str(config_path))
    profiles = []
    for section in config.sections():
        if section == "default":
            profiles.append("default")
        elif section.startswith("profile "):
            profiles.append(section.split(" ", 1)[1])
    if "default" not in profiles:
        profiles.insert(0, "default")
    return profiles


def accounts_from_profiles(profiles: list[str]) -> list[dict]:
    """Discover account ID and alias for each named profile via STS."""
    seen = set()
    accounts = []
    for profile in profiles:
        try:
            session = boto3.Session(profile_name=profile)
            sts = session.client("sts", region_name=session.region_name or "us-east-1")
            identity = sts.get_caller_identity()
            acct_id = identity["Account"]
            if acct_id in seen:
                continue
            seen.add(acct_id)

            name = profile
            try:
                iam = session.client("iam", region_name=session.region_name or "us-east-1")
                aliases = iam.list_account_aliases().get("AccountAliases", [])
                if aliases:
                    name = aliases[0]
            except (ClientError, BotoCoreError):
                pass

            accounts.append({
                "id": acct_id,
                "name": name,
                "profile": profile,
            })
        except (ClientError, NoCredentialsError, BotoCoreError) as e:
            print(f"  SKIP profile '{profile}': {e}")
    return accounts


# ---------------------------------------------------------------------------
# Main discovery
# ---------------------------------------------------------------------------

def discover(args) -> list[dict]:
    """Try Org → SSO → profiles, return the first that works."""

    # If the user explicitly asked for profiles, skip the other methods
    if args.profiles or args.from_profiles:
        profiles = args.profiles or list_config_profiles()
        print(f"Discovering accounts from {len(profiles)} CLI profile(s)...")
        accounts = accounts_from_profiles(profiles)
        print(f"  Found {len(accounts)} unique account(s) via profiles")
        return accounts

    # Method 1: Organizations
    print("Trying AWS Organizations...")
    session = boto3.Session()
    accounts = try_organizations(session)
    if accounts is not None:
        print(f"  Found {len(accounts)} active account(s) via Organizations")
        return accounts
    print("  Organizations not available (access denied or not in an org)")

    # Method 2: SSO
    print("Trying AWS SSO cache...")
    accounts = try_sso()
    if accounts is not None:
        print(f"  Found {len(accounts)} account(s) via SSO")
        return accounts
    print("  No valid SSO tokens found")

    # Method 3: profiles
    profiles = list_config_profiles()
    print(f"Falling back to CLI profiles ({len(profiles)} found)...")
    accounts = accounts_from_profiles(profiles)
    print(f"  Found {len(accounts)} unique account(s) via profiles")
    return accounts


def main():
    parser = argparse.ArgumentParser(
        description="Discover AWS accounts and write accounts.json for the sizing script.",
    )
    parser.add_argument(
        "--output", "-o", default="accounts.json",
        help="Output file path (default: accounts.json)",
    )
    parser.add_argument(
        "--profiles", nargs="+", default=None,
        help="Explicit list of AWS CLI profile names to use (skips Org and SSO discovery)",
    )
    parser.add_argument(
        "--from-profiles", action="store_true",
        help="Auto-discover all profiles from ~/.aws/config (skips Org and SSO discovery)",
    )
    args = parser.parse_args()

    accounts = discover(args)

    if not accounts:
        print("ERROR: No accounts discovered. Check your AWS credentials.")
        sys.exit(1)

    with open(args.output, "w") as f:
        json.dump(accounts, f, indent=2)
    print(f"\nWrote {len(accounts)} account(s) to {args.output}")
    if all("profile" in a for a in accounts):
        profiles = " ".join(a["profile"] for a in accounts)
        print(f"Next: python collect_log_sizing.py --profiles {profiles}")
    else:
        print(f"Next: python collect_log_sizing.py --accounts-file {args.output} --role-name CoralogixLogSizingRole")


if __name__ == "__main__":
    main()
