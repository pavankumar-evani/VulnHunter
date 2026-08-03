"""One-time setup script to create the demo SQLite DB with a couple of seed users."""
import sqlite3

conn = sqlite3.connect("vulnshop.db")
cursor = conn.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT,
        password TEXT
    )
    """
)
cursor.execute(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    ("alice", "alice@example.com", "hunter2"),
)
cursor.execute(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    ("bob", "bob@example.com", "password123"),
)
conn.commit()
conn.close()
print("vulnshop.db created with seed users.")
