#!/usr/bin/env python3
import argparse
import csv
import json
import os
from typing import Any, Dict, List

def parse_policy_csv(path: str) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f, skipinitialspace=True)
        for row in reader:
            if not row:
                continue
            # allow comments with leading '#'
            if row[0].strip().startswith("#"):
                continue

            # Casbin policy lines look like:
            # p, alice, data1, read
            # g, alice, admin
            ptype = row[0].strip()
            fields = [c.strip() for c in row[1:]]

            rules.append({"ptype": ptype, "fields": fields, "raw": row})
    return rules

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy-file", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rules = parse_policy_csv(args.policy_file)

    payload = {
        "casbin": {
            "policy_file": os.path.basename(args.policy_file),
            "rules": rules
        }
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
