"""Run all V1 login security detection rules once."""

import os

from dotenv import load_dotenv
import psycopg
from psycopg.rows import dict_row

from api.detection import run_detection


def main() -> None:
    load_dotenv()
    required = ("DB_NAME", "DB_USER", "DB_PASSWORD")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise SystemExit(
            "Missing database settings: " + ", ".join(missing)
            + ". Copy .env.example to .env and set your local credentials."
        )

    try:
        with psycopg.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
            connect_timeout=5,
            row_factory=dict_row,
        ) as conn:
            summary = run_detection(conn)
    except psycopg.Error as exc:
        raise SystemExit(f"Detection failed to connect or query PostgreSQL: {exc}") from exc

    total = sum(summary.values())
    print(f"Created {total} new alerts.")
    for rule, count in summary.items():
        print(f"  {rule.removeprefix('detect_').replace('_', ' ')}: {count}")
    print("Safe to rerun: duplicate detections are suppressed by dedupe_key.")


if __name__ == "__main__":
    main()
