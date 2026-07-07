from __future__ import annotations

import argparse
from pathlib import Path

from app.audit_export import build_audit_package
from app.config import audit_hmac_key, audit_log_path, policy_data_path
from app.policy import tenant_policy_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an ASG auditor export package (.tar.gz).")
    parser.add_argument("--out", required=True, help="Output .tar.gz path")
    parser.add_argument("--tenant-id", default=None, help="Limit export to one tenant")
    parser.add_argument("--audit-path", default=None, help="Override audit log path")
    parser.add_argument("--policy-path", default=None, help="Override policy snapshot path")
    args = parser.parse_args()

    audit_path = Path(args.audit_path) if args.audit_path else audit_log_path()
    if args.policy_path:
        policy_path = Path(args.policy_path)
    elif args.tenant_id and (tp := tenant_policy_path(args.tenant_id)) is not None and tp.is_file():
        policy_path = tp
    else:
        policy_path = policy_data_path()

    package = build_audit_package(
        audit_path=audit_path,
        policy_path=policy_path,
        tenant_id=args.tenant_id,
        hmac_key=audit_hmac_key(),
    )
    Path(args.out).write_bytes(package)
    print(args.out)


if __name__ == "__main__":
    main()
