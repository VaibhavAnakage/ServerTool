#!/usr/bin/env python3
import argparse
import sqlite3
import os
import sys
from werkzeug.security import generate_password_hash

DB_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'monitoring.db')


def upsert_api_user(email: str, password: str, name: str = 'API User'):
    email = (email or '').strip().lower()
    if not email or not password:
        raise ValueError('email and password are required')
    pw_hash = generate_password_hash(password)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        row = c.fetchone()
        if row:
            c.execute(
                "UPDATE users SET name=COALESCE(name, ?), password_hash=?, role='api', location=NULL WHERE email=?",
                (name, pw_hash, email)
            )
            action = 'updated'
        else:
            c.execute(
                "INSERT INTO users(name, email, password_hash, role, location) VALUES(?, ?, ?, 'api', NULL)",
                (name, email, pw_hash)
            )
            action = 'created'
        conn.commit()
        c.execute("SELECT id, email, role FROM users WHERE email=?", (email,))
        final = c.fetchone()
        return action, dict(final)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description='Create or update API user (role=api) for metrics ingestion.')
    parser.add_argument('--email', required=True, help='Email/username for API user (Basic Auth username)')
    parser.add_argument('--password', required=True, help='Password for API user (Basic Auth password)')
    parser.add_argument('--name', default='API User', help='Display name for the API user')
    args = parser.parse_args()
    action, final_user = upsert_api_user(args.email, args.password, args.name)
    print(f"API user {action}: {final_user}")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
