#!/usr/bin/env bash
# Export all ACTIVE AWS Organization accounts to accounts.json
# Run this from your management account or delegated-admin account.
# Output format matches --accounts-file expected by collect_log_sizing.py

set -euo pipefail

OUTPUT="accounts.json"

echo "Listing active accounts from AWS Organizations..."

aws organizations list-accounts \
  --query 'Accounts[?Status==`ACTIVE`].[Id, Name]' \
  --output json \
| python3 -c "
import json, sys
raw = json.load(sys.stdin)
accounts = [{'id': row[0], 'name': row[1]} for row in raw]
print(json.dumps(accounts, indent=2))
" > "$OUTPUT"

COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT'))))")
echo "Exported $COUNT accounts to $OUTPUT"
