"""Explicit schema bootstrap: no application startup, collectors, scans or seed users."""
import argparse
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--apply", action="store_true", help="Create missing tables after reviewing the target database")
    args = parser.parse_args()
    if not args.apply:
        parser.error("Review the database destination and migrations first, then pass --apply.")
    if not args.env_file.is_file():
        parser.error("The supplied private environment file does not exist.")
    from dotenv import load_dotenv
    load_dotenv(args.env_file.resolve(), override=True)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from schema_initialization import initialize_database, verify_database_schema
    initialize_database()
    verify_database_schema()
    print("SCHEMA_INITIALIZED: all registered ORM tables and required asset column present.")
    print("No users, permissions, scans or background services were started. Review versioned migrations separately.")


if __name__ == "__main__":
    main()
