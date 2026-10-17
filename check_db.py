
import sqlite3
from pathlib import Path

db_path = Path(__file__).parent / "datalens_data" / "datalens.db"

if not db_path.exists():
    print(f"Database not found: {db_path}")
else:
    connection = sqlite3.connect(db_path)

    try:
        tables = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = ? ORDER BY name",
            ("table",)
        ).fetchall()

        for (table_name,) in tables:
            print(f"\n--- {table_name} ---")

            # Quote the table name safely for PRAGMA.
            safe_name = table_name.replace('"', '""')
            columns = connection.execute(
                f'PRAGMA table_info("{safe_name}")'
            ).fetchall()

            for column in columns:
                print(column)
    finally:
        connection.close()
