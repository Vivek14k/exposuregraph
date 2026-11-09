import argparse
from getpass import getpass
import sys

from backend.core.auth import create_user, normalize_email
from backend.database.models import SessionLocal, User


def create_account(email: str, claim_legacy_scans: bool) -> int:
    password = getpass("Password (12–256 characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        print("Passwords do not match.", file=sys.stderr)
        return 2

    db = SessionLocal()
    try:
        user = create_user(db, email, password, claim_legacy_scans=claim_legacy_scans)
        print(f"Created account for {user.email}.")
        if claim_legacy_scans:
            print("Unowned legacy scans were assigned to this account.")
        return 0
    except ValueError as exc:
        db.rollback()
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="ExposureGraph local administration commands")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create-user", help="Create an account without exposing registration publicly")
    create.add_argument("email")
    create.add_argument(
        "--claim-legacy-scans",
        action="store_true",
        help="Assign all unowned pre-authentication scans to this account; use only for a single-owner database.",
    )
    args = parser.parse_args()
    try:
        email = normalize_email(args.email)
    except ValueError as exc:
        parser.error(str(exc))
    return create_account(email, args.claim_legacy_scans)


if __name__ == "__main__":
    raise SystemExit(main())
