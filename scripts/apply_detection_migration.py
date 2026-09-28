"""Apply the additive detection migration using the local .env settings."""

from pathlib import Path
import os

from dotenv import load_dotenv
import psycopg


def main() -> None:
    load_dotenv()
    required = ("DB_NAME", "DB_USER", "DB_PASSWORD")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise SystemExit("Missing database settings in .env: " + ", ".join(missing))

    migration_path = Path(__file__).resolve().parents[1] / "sql" / "upgrade_detection.sql"
    statements = [statement.strip() for statement in migration_path.read_text(encoding="utf-8").split(";") if statement.strip()]
    with psycopg.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)
    print(f"Applied {len(statements)} detection migration statements to {os.environ['DB_NAME']}.")


if __name__ == "__main__":
    main()
