import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

DATABASE = Path(__file__).resolve().parent / "portal.db"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    connection.execute("""
        INSERT OR IGNORE INTO users
        (username, password, email)
        VALUES (?, ?, ?)
    """, (
        "admin",
        generate_password_hash("admin123"),
        "admin@support.local"
    ))

    connection.execute("""
        INSERT OR IGNORE INTO tickets
        (id, title, description, status)
        VALUES (?, ?, ?, ?)
    """, (
        1,
        "VPN connection problem",
        "User cannot connect to the company VPN.",
        "Open"
    ))

    connection.execute("""
        INSERT OR IGNORE INTO tickets
        (id, title, description, status)
        VALUES (?, ?, ?, ?)
    """, (
        2,
        "Printer issue",
        "The printer on the second floor is not responding.",
        "Closed"
    ))

    connection.commit()
    connection.close()


if __name__ == "__main__":
    init_db()
    print("Database initialized.")
