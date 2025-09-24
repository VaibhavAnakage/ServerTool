import sqlite3
from werkzeug.security import generate_password_hash

DB_FILE = "monitoring.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Drop old tables
    c.execute("DROP TABLE IF EXISTS domains")
    c.execute("DROP TABLE IF EXISTS domain_alerts")
    c.execute("DROP TABLE IF EXISTS servers")
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS locations")

    # Domains table
    c.execute("""
        CREATE TABLE domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            registrar TEXT,
            creation_date TEXT,
            expiration_date TEXT,
            ssl_issuer TEXT,
            ssl_expiry TEXT,
            location TEXT
        )
    """)

    # Domain alerts table
    c.execute("""
        CREATE TABLE domain_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_name TEXT UNIQUE NOT NULL,
            recipients TEXT,
            days_before INTEGER,
            send_once INTEGER DEFAULT 0,
            sent INTEGER DEFAULT 0,
            frequency TEXT DEFAULT 'once', -- once, daily, weekly, monthly
            end_date TEXT,                 -- ISO date YYYY-MM-DD for termination
            last_sent TEXT,               -- ISO datetime of last email sent
            active INTEGER DEFAULT 1,     -- 1=enabled, 0=terminated/disabled
            FOREIGN KEY(domain_name) REFERENCES domains(name)
        )
    """)

    # Server monitoring table
    c.execute("""
        CREATE TABLE IF NOT EXISTS server_monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            hostname TEXT NOT NULL,
            os TEXT,
            cpu_count INTEGER,
            cpu_usage REAL,
            memory_total REAL,
            memory_used REAL,
            memory_percent REAL,
            disk_total REAL,
            disk_used REAL,
            disk_percent REAL,
            open_ports TEXT,
            status TEXT DEFAULT 'online'
        )
    """)

    # Servers inventory table
    c.execute("""
        CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            location TEXT,
            alive INTEGER DEFAULT 0,
            last_ping_at TEXT
        )
    """)

    # Users table
    c.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,          -- super_admin, admin, super_analytics, analytics
            location TEXT                -- required for admin/analytics
        )
    """)

    # Locations table
    c.execute("""
        CREATE TABLE locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)

    # Seed locations
    for city in ("Bangalore","Mumbai","Delhi","Chennai","Hyderabad"):
        c.execute("INSERT OR IGNORE INTO locations(name) VALUES (?)", (city,))

    # Seed users
    users = [
        ("Super Admin", "anakage@anakage.com", generate_password_hash("Anakage@123"), "super_admin", None),
        ("Vaibhav", "vaibhav@anakage.com", generate_password_hash("Anakage@123"), "admin", "Bangalore"),
        ("Jyoti", "jyoti@anakage.com", generate_password_hash("Anakage@123"), "analytics", "Mumbai")
    ]
    for name, email, pwd, role, loc in users:
        c.execute("""
            INSERT OR IGNORE INTO users(name, email, password_hash, role, location)
            VALUES (?, ?, ?, ?, ?)
        """, (name, email, pwd, role, loc))

    conn.commit()
    conn.close()
    print("✅ Database initialized with tables: domains, domain_alerts, server_monitoring, servers, users, locations")

    # Create index for faster queries
    c.execute("CREATE INDEX IF NOT EXISTS idx_server_monitoring_timestamp ON server_monitoring(timestamp)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_server_monitoring_hostname ON server_monitoring(hostname)")

    conn.commit()
    conn.close()
    print("✅ Database initialized with tables: domains, domain_alerts, server_monitoring")

if __name__ == "__main__":
    init_db()
