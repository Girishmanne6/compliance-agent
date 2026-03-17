from __future__ import annotations

import sqlite3
from pathlib import Path

DATABASE_PATH = Path("/tmp/compliance-agent.db")



def fetch_user(user_id: int) -> list[tuple]:
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        return cursor.fetchall()
