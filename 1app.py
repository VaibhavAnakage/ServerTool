from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import ssl, socket, datetime, whois, platform, psutil, sqlite3, smtplib, subprocess, functools, os, traceback, threading, time
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = "replace-with-your-secret"  # for flash messages
DB_FILE = "monitoring.db"

# ---------------- SMTP CONFIG ----------------
# Replace with your SMTP details
SMTP_CONFIG = {
    "host": "smtp.zoho.com",
    "port": 587,
    "username": "itsm.admin@anakage.com",
    "password": "2dRtvaaN806y",
    "use_tls": True,
    "from_addr": "itsm.admin@anakage.com"
}
# ---------------------------------------------

# ---------- DB Helper ----------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Cross-platform ping helper
def ping_host(target: str, timeout_seconds: int = 3) -> bool:
    """Ping target once and return True if reachable.
    Windows: ping -n 1 -w <ms>
    Unix:    ping -c 1 -W <sec>
    """
    try:
        is_win = platform.system().lower().startswith('win')
        count_flag = '-n' if is_win else '-c'
        timeout_flag = '-w' if is_win else '-W'
        timeout_value = str(int(timeout_seconds * 1000)) if is_win else str(int(timeout_seconds))
        cmd = ['ping', count_flag, '1', timeout_flag, timeout_value, target]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds + 2)
        return result.returncode == 0
    except Exception:
        return False

# ---------- DB Migration Helpers ----------
def ensure_alerts_schema():
    """Add new columns to domain_alerts if they do not exist."""
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("ALTER TABLE domain_alerts ADD COLUMN frequency TEXT DEFAULT 'once'")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE domain_alerts ADD COLUMN end_date TEXT")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE domain_alerts ADD COLUMN last_sent TEXT")
    except Exception:
        pass
    try:
        c.execute("ALTER TABLE domain_alerts ADD COLUMN active INTEGER DEFAULT 1")
    except Exception:
        pass
    conn.commit()
    conn.close()

ensure_alerts_schema()

# ---------- Server Status Schema ----------
def ensure_server_status_schema():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS server_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            cpu_usage REAL,
            memory_usage REAL,
            total_disk REAL,
            used_disk REAL,
            disk_percent REAL,
            last_updated TEXT,
            FOREIGN KEY(server_id) REFERENCES servers(id)
        )
        """
    )
    conn.commit()
    conn.close()

ensure_server_status_schema()

# ---------- Server Alerts Schema ----------
def ensure_server_alerts_schema():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS server_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            email_address TEXT NOT NULL,
            last_alert_sent TEXT,
            UNIQUE(server_id, email_address),
            FOREIGN KEY(server_id) REFERENCES servers(id)
        )
        """
    )
    conn.commit()
    conn.close()

ensure_server_alerts_schema()

# ---------- Auth & RBAC Helpers ----------
def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, email, role, location FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row

def login_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapper

def is_read_only(user):
    return user and user["role"] in ("super_analytics", "analytics")

def user_can_access_location(user, location):
    if not user:
        return False
    role = user["role"]
    if role in ("super_admin", "super_analytics"):
        return True
    if role in ("admin", "analytics"):
        return (user["location"] or "").lower() == (location or "").lower()
    return False

def rbac_allow_all_locations(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapper

def rbac_write_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for('login'))
        if is_read_only(user):
            flash("You have read-only access.", "warning")
            return redirect(request.referrer or url_for('index'))
        return view_func(*args, **kwargs)
    return wrapper

# ---------- Auth Routes ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    from werkzeug.security import check_password_hash
    if row and check_password_hash(row["password_hash"], password):
        session['user_id'] = row["id"]
        flash("Logged in successfully.", "success")
        return redirect(request.args.get('next') or url_for('index'))
    flash("Invalid credentials.", "danger")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# ---------- Domain Info ----------
def fetch_domain_info(domain_name):
    domain_info = {}
    ssl_info = {}

    # WHOIS
    try:
        w = whois.whois(domain_name)
        domain_info = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expiration_date": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date)
        }
    except Exception as e:
        domain_info = {"registrar": None, "creation_date": None, "expiration_date": None}

    # SSL
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain_name) as s:
            s.settimeout(5.0)
            s.connect((domain_name, 443))
            cert = s.getpeercert()
            ssl_expiry = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            ssl_info = {
                "issuer": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                "expiry_date": ssl_expiry.strftime("%Y-%m-%d")
            }
    except Exception:
        ssl_info = {"issuer": None, "expiry_date": None}

    return {**domain_info, **ssl_info}

# ---------- Email Sender ----------
def send_email_smtp(to_addresses, subject, body):
    if not isinstance(to_addresses, (list, tuple)):
        to_addresses = [a.strip() for a in to_addresses.split(",") if a.strip()]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_CONFIG.get("from_addr", SMTP_CONFIG.get("username"))
    msg["To"] = ", ".join(to_addresses)
    msg.set_content(body)

    try:
        if SMTP_CONFIG.get("use_tls"):
            server = smtplib.SMTP(SMTP_CONFIG["host"], SMTP_CONFIG["port"], timeout=15)
            server.starttls()
            server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
        else:
            server = smtplib.SMTP_SSL(SMTP_CONFIG["host"], SMTP_CONFIG["port"], timeout=15)
            server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])

        server.send_message(msg)
        server.quit()
        return True, None
    except Exception as e:
        return False, str(e)

# ---------- Routes ----------
@app.route('/')
@login_required
def index():
    user = get_current_user()
    # Fetch a small summary for dashboard
    conn = get_db_connection()
    c = conn.cursor()
    # Domains count (filtered by role/location)
    if user and user["role"] in ("admin", "analytics"):
        c.execute("SELECT COUNT(*) FROM domains WHERE LOWER(COALESCE(location,''))=LOWER(?)", (user["location"] or '',))
    else:
        c.execute("SELECT COUNT(*) FROM domains")
    domains_count = c.fetchone()[0]

    # Recent servers list (filtered by role/location)
    base_sql = "SELECT id, name, ip_address, location, alive, last_ping_at FROM servers"
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY name LIMIT 10"
    c.execute(base_sql, params)
    servers = c.fetchall()
    conn.close()

    return render_template('index.html', user=user, domains_count=domains_count, servers=servers)

def get_locations():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name FROM locations ORDER BY name")
    rows = [r[0] for r in c.fetchall()]
    conn.close()
    return rows

@app.route('/domain', methods=['GET', 'POST'])
@login_required
def domain():
    conn = get_db_connection()
    c = conn.cursor()
    user = get_current_user()

    if request.method == 'POST':
        if is_read_only(user):
            flash("You have read-only access.", "warning")
            return redirect(url_for('domain'))
        domain_name = request.form.get('domain_name', '').strip().lower()
        location = request.form.get('location', '').strip()
        if not domain_name:
            flash("Please provide a domain name.", "warning")
            return redirect(url_for('domain'))

        # RBAC: Admin/Analytics limited to their location
        if not user_can_access_location(user, location):
            flash("You cannot add domains for this location.", "danger")
            return redirect(url_for('domain'))

        # Check if domain exists in DB
        c.execute("SELECT * FROM domains WHERE name = ?", (domain_name,))
        existing = c.fetchone()

        if not existing:
            info = fetch_domain_info(domain_name)
            c.execute('''INSERT OR IGNORE INTO domains 
                        (name, registrar, creation_date, expiration_date, ssl_issuer, ssl_expiry, location) 
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (domain_name, 
                         info.get("registrar"), 
                         info.get("creation_date"), 
                         info.get("expiration_date"), 
                         info.get("issuer"), 
                         info.get("expiry_date"),
                         location))
            conn.commit()
            flash(f"Domain {domain_name} added.", "success")
        else:
            flash(f"Domain {domain_name} already exists.", "info")

        conn.close()
        return redirect(url_for('domain'))

    # Fetch all domains and their alert settings
    base_sql = """
        SELECT d.name, d.registrar, d.creation_date, d.expiration_date, d.ssl_issuer, d.ssl_expiry, d.location,
               a.recipients, a.days_before, a.send_once, a.sent, a.frequency, a.end_date, a.active, a.last_sent
        FROM domains d
        LEFT JOIN domain_alerts a ON a.domain_name = d.name
    """
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(d.location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY d.name"
    c.execute(base_sql, params)
    rows = c.fetchall()
    domains = []
    now = datetime.datetime.now()

    for r in rows:
        ssl_expiry = r["ssl_expiry"]
        days_left = None
        try:
            if ssl_expiry:
                expiry_dt = datetime.datetime.strptime(ssl_expiry, "%Y-%m-%d")
                days_left = (expiry_dt - now).days
        except Exception:
            days_left = None

        domains.append({
            "name": r["name"],
            "registrar": r["registrar"],
            "creation_date": r["creation_date"],
            "expiration_date": r["expiration_date"],
            "ssl_issuer": r["ssl_issuer"],
            "ssl_expiry": r["ssl_expiry"],
            "location": r["location"],
            "days_left": days_left,
            "alert_recipients": r["recipients"],
            "alert_days_before": r["days_before"],
            "alert_send_once": bool(r["send_once"]) if r["send_once"] is not None else False,
            "alert_sent": bool(r["sent"]) if r["sent"] is not None else False,
            "alert_frequency": r["frequency"],
            "alert_end_date": r["end_date"],
            "alert_active": bool(r["active"]) if r["active"] is not None else True,
            "alert_last_sent": r["last_sent"]
        })

    conn.close()
    return render_template('domain.html', domains=domains, now=now.date(), locations=get_locations(), user=user)

@app.route('/domain/edit/<path:domain_name>', methods=['GET', 'POST'])
@login_required
@rbac_write_required
def edit_domain(domain_name):
    """Edit domain properties. Currently only allows updating location (name immutable)."""
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name, registrar, creation_date, expiration_date, ssl_issuer, ssl_expiry, location FROM domains WHERE name=?", (domain_name,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Domain not found.", "danger")
        return redirect(url_for('domain'))
    if not user_can_access_location(user, row["location"]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('domain'))

    if request.method == 'POST':
        location = request.form.get('location', '').strip()
        if not user_can_access_location(user, location):
            flash("You cannot set this domain's location.", "danger")
            conn.close()
            return redirect(url_for('edit_domain', domain_name=domain_name))
        try:
            c.execute("UPDATE domains SET location=? WHERE name=?", (location, domain_name))
            conn.commit()
            flash("Domain updated.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Failed to update domain: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('domain'))

    domain_row = {
        "name": row["name"],
        "registrar": row["registrar"],
        "creation_date": row["creation_date"],
        "expiration_date": row["expiration_date"],
        "ssl_issuer": row["ssl_issuer"],
        "ssl_expiry": row["ssl_expiry"],
        "location": row["location"],
    }
    conn.close()
    return render_template('domain_edit.html', domain=domain_row, locations=get_locations(), user=user)

@app.route('/alert', methods=['GET', 'POST'])
@login_required
def alert():
    if request.method == 'GET':
        domain_name = request.args.get('domain_name', '')
        return render_template('alert_form.html', domain_name=domain_name)

    # POST -> save alert settings
    domain_name = request.form.get('domain_name', '').strip().lower()
    recipients = request.form.get('recipients', '').strip()
    days_before = int(request.form.get('days_before', '30'))
    send_once = 1 if request.form.get('send_once') == 'on' else 0
    frequency = request.form.get('frequency', 'once')
    end_date = request.form.get('end_date', '').strip() or None
    active = 0 if request.form.get('terminate') == 'on' else 1

    conn = get_db_connection()
    c = conn.cursor()
    # Insert or update
    c.execute("""
        INSERT INTO domain_alerts(domain_name, recipients, days_before, send_once, sent, frequency, end_date, active, last_sent)
        VALUES (?, ?, ?, ?, 0, ?, ?, ?, NULL)
        ON CONFLICT(domain_name) DO UPDATE SET
            recipients=excluded.recipients,
            days_before=excluded.days_before,
            send_once=excluded.send_once,
            frequency=excluded.frequency,
            end_date=excluded.end_date,
            active=excluded.active,
            sent=CASE WHEN excluded.send_once=1 OR excluded.frequency='once' THEN 0 ELSE sent END,
            last_sent=NULL
    """, (domain_name, recipients, days_before, send_once, frequency, end_date, active))
    conn.commit()
    conn.close()
    flash(f"Alert saved for {domain_name}. It will trigger {days_before} days before expiry (frequency: {frequency}).", "success")
    return redirect(url_for('domain'))

@app.route('/run_alerts', methods=['GET'])
@login_required
def run_alerts():
    """
    Evaluate alerts and send emails if criteria match.
    This endpoint can be called manually or via cron/scheduler (e.g., daily).
    """
    conn = get_db_connection()
    c = conn.cursor()

    # Fetch alerts that are active and have recipients
    c.execute("""
        SELECT a.id, a.domain_name, a.recipients, a.days_before, a.send_once, a.sent,
               a.frequency, a.end_date, a.last_sent, a.active,
               d.ssl_expiry
        FROM domain_alerts a
        JOIN domains d ON d.name = a.domain_name
        WHERE a.active = 1 AND a.recipients IS NOT NULL AND a.recipients <> ''
    """)
    alerts = c.fetchall()
    now = datetime.datetime.now()
    results = []

    for a in alerts:
        domain = a["domain_name"]
        recipients = a["recipients"]
        days_before = a["days_before"] or 0
        send_once = bool(a["send_once"])
        frequency = a["frequency"] or 'once'
        end_date = a["end_date"]
        last_sent = a["last_sent"]
        ssl_expiry = a["ssl_expiry"]

        if not ssl_expiry:
            results.append((domain, "no-ssl-expiry"))
            continue

        try:
            expiry_dt = datetime.datetime.strptime(ssl_expiry, "%Y-%m-%d")
        except Exception:
            results.append((domain, "invalid-ssl-format"))
            continue

        days_left = (expiry_dt - now).days

        # Termination by end_date
        if end_date:
            try:
                if now.date() > datetime.datetime.strptime(end_date, "%Y-%m-%d").date():
                    results.append((domain, "terminated"))
                    c.execute("UPDATE domain_alerts SET active=0 WHERE domain_name=?", (domain,))
                    conn.commit()
                    continue
            except Exception:
                pass

        # Not due yet based on proximity
        if days_left > days_before:
            results.append((domain, f"not-due ({days_left} days left)"))
            continue

        # Evaluate frequency throttle using last_sent
        should_send = True
        if last_sent:
            try:
                last_dt = datetime.datetime.fromisoformat(last_sent)
            except Exception:
                try:
                    last_dt = datetime.datetime.strptime(last_sent, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    last_dt = None

            if last_dt:
                delta = now - last_dt
                if frequency == 'daily' and delta.days < 1:
                    should_send = False
                elif frequency == 'weekly' and delta.days < 7:
                    should_send = False
                elif frequency == 'monthly' and delta.days < 28:
                    should_send = False
                elif frequency == 'once' and a["sent"] == 1:
                    should_send = False

        if not should_send:
            results.append((domain, f"throttled ({frequency})"))
            continue

        # Send mail
        subject = f"[ALERT] SSL expiry for {domain} in {days_left} day(s)"
        body = f"Domain: {domain}\nSSL expiry date: {ssl_expiry}\nDays left: {days_left}\nThis alert was configured for {days_before} days-before."
        success, error = send_email_smtp(recipients, subject, body)
        if success:
            results.append((domain, "emailed"))
            if send_once or frequency == 'once':
                c.execute("UPDATE domain_alerts SET sent = 1, last_sent = ? WHERE domain_name = ?", (now.isoformat(sep=' ', timespec='seconds'), domain))
            else:
                c.execute("UPDATE domain_alerts SET last_sent = ? WHERE domain_name = ?", (now.isoformat(sep=' ', timespec='seconds'), domain))
            conn.commit()
        else:
            results.append((domain, f"email-error: {error}"))

    conn.close()
    # Return a small summary for quick checks
    return {"results": results}

@app.route('/server', methods=['GET', 'POST'])
@login_required
def server():
    user = get_current_user()
    if request.method == 'POST':
        if is_read_only(user):
            flash("You have read-only access.", "warning")
            return redirect(url_for('server'))
        conn = get_db_connection()
        c = conn.cursor()
        name = request.form.get('name', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        location = request.form.get('location', '').strip()
        # Default location for Admin/Analytics if not explicitly selected
        if not location and user and user["role"] in ("admin", "analytics"):
            location = user["location"] or ''
        if not user_can_access_location(user, location):
            flash("You cannot add servers for this location.", "danger")
            return redirect(url_for('server'))
        if not name or not ip_address:
            flash("Name and IP address are required.", "warning")
            return redirect(url_for('server'))
        try:
            c.execute("INSERT INTO servers(name, ip_address, location) VALUES(?, ?, ?)", (name, ip_address, location))
            conn.commit()
            flash("Server added.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Failed to add server: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('server'))

    # Skip local stats collection by default
    collect_local = os.environ.get('COLLECT_LOCAL_STATS', '0') == '1'
    if collect_local:
        try:
            hostname = platform.node()
            os_info = f"{platform.system()} {platform.release()}"
            cpu_count = psutil.cpu_count(logical=True)
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            try:
                disk_root = os.environ.get("DISK_ROOT") or os.getenv('SystemDrive') or os.path.abspath(os.sep)
                if isinstance(disk_root, bytes):
                    disk_root = disk_root.decode('utf-8', 'ignore')
                disk_root = (disk_root or '').strip()
                if platform.system().lower().startswith('win') and len(disk_root) == 2 and disk_root[1] == ':':
                    disk_root = disk_root + '\\'
                disk_root = os.path.normpath(disk_root)
                if not os.path.isabs(disk_root):
                    disk_root = os.path.abspath(disk_root)
                print("[server] disk_root=", repr(disk_root), type(disk_root))
                disk = psutil.disk_usage(disk_root)
            except Exception as disk_err:
                try:
                    fallback_root = os.path.abspath(os.path.expanduser('~'))
                    print("[server] fallback_root=", repr(fallback_root), type(fallback_root))
                    disk = psutil.disk_usage(fallback_root)
                except Exception as disk_err2:
                    final_root = os.path.abspath(os.sep)
                    print("[server] final_root=", repr(final_root), type(final_root))
                    disk = psutil.disk_usage(final_root)

            open_ports = []
            for port in [22, 80, 443]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    open_ports.append(port)
                sock.close()

            conn = get_db_connection()
            c = conn.cursor()
            c.execute('''
                INSERT INTO server_monitoring 
                (hostname, os, cpu_count, cpu_usage, memory_total, memory_used, memory_percent, 
                 disk_total, disk_used, disk_percent, open_ports, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                hostname,
                os_info,
                cpu_count,
                cpu_percent,
                round(memory.total / (1024**3), 2),
                round(memory.used / (1024**3), 2),
                memory.percent,
                round(disk.total / (1024**3), 2),
                round(disk.used / (1024**3), 2),
                round((disk.used / disk.total) * 100, 2),
                ','.join(map(str, open_ports)),
                'online'
            ))
            conn.commit()
            conn.close()

            server_info = {
                "hostname": hostname,
                "os": os_info,
                "cpu_count": cpu_count,
                "cpu_usage": f"{cpu_percent}%",
                "memory_total": f"{round(memory.total / (1024**3),2)} GB",
                "memory_used": f"{round(memory.used / (1024**3),2)} GB",
                "memory_percent": f"{memory.percent}%",
                "disk_total": f"{round(disk.total / (1024**3), 2)} GB",
                "disk_used": f"{round(disk.used / (1024**3), 2)} GB",
                "disk_percent": f"{round((disk.used / disk.total) * 100, 2)}%",
                "open_ports": open_ports
            }
        except Exception as e:
            server_info = {"error": f"server_info_failure: {type(e).__name__}: {e} | trace: {traceback.format_exc()}"}
    else:
        server_info = None

    # Load servers
    conn = get_db_connection()
    c = conn.cursor()
    base_sql = "SELECT id, name, ip_address, location, alive, last_ping_at FROM servers"
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY name"
    c.execute(base_sql, params)
    servers = c.fetchall()
    conn.close()

    return render_template('server.html', server_info=server_info, servers=servers, locations=get_locations(), user=user)

@app.route('/server/edit/<int:server_id>', methods=['GET', 'POST'])
@login_required
@rbac_write_required
def edit_server(server_id):
    """Edit server details (name, IP, location) with RBAC location checks"""
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, ip_address, location FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Server not found.", "danger")
        return redirect(url_for('server'))
    # RBAC: view/edit allowed only in location scope for admin/analytics
    if not user_can_access_location(user, row["location"]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('server'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        location = request.form.get('location', '').strip()
        if not name or not ip_address:
            flash("Name and IP address are required.", "warning")
            conn.close()
            return redirect(url_for('edit_server', server_id=server_id))
        if not user_can_access_location(user, location):
            flash("You cannot set this server's location.", "danger")
            conn.close()
            return redirect(url_for('edit_server', server_id=server_id))
        try:
            c.execute("UPDATE servers SET name=?, ip_address=?, location=? WHERE id=?", (name, ip_address, location, server_id))
            conn.commit()
            flash("Server updated.", "success")
        except Exception as e:
            conn.rollback()
            flash(f"Failed to update server: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for('server'))

    # GET -> render edit form
    server_row = {"id": row["id"], "name": row["name"], "ip_address": row["ip_address"], "location": row["location"]}
    conn.close()
    return render_template('server_edit.html', server=server_row, locations=get_locations(), user=user)

    # Skip local stats collection by default
    collect_local = os.environ.get('COLLECT_LOCAL_STATS', '0') == '1'
    if collect_local:
        try:
            hostname = platform.node()
            os_info = f"{platform.system()} {platform.release()}"
            cpu_count = psutil.cpu_count(logical=True)
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            try:
                disk_root = os.environ.get("DISK_ROOT") or os.getenv('SystemDrive') or os.path.abspath(os.sep)
                if isinstance(disk_root, bytes):
                    disk_root = disk_root.decode('utf-8', 'ignore')
                disk_root = (disk_root or '').strip()
                if platform.system().lower().startswith('win') and len(disk_root) == 2 and disk_root[1] == ':':
                    disk_root = disk_root + '\\'
                disk_root = os.path.normpath(disk_root)
                if not os.path.isabs(disk_root):
                    disk_root = os.path.abspath(disk_root)
                print("[server] disk_root=", repr(disk_root), type(disk_root))
                disk = psutil.disk_usage(disk_root)
            except Exception as disk_err:
                try:
                    fallback_root = os.path.abspath(os.path.expanduser('~'))
                    print("[server] fallback_root=", repr(fallback_root), type(fallback_root))
                    disk = psutil.disk_usage(fallback_root)
                except Exception as disk_err2:
                    final_root = os.path.abspath(os.sep)
                    print("[server] final_root=", repr(final_root), type(final_root))
                    disk = psutil.disk_usage(final_root)

            open_ports = []
            for port in [22, 80, 443]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    open_ports.append(port)
                sock.close()

            conn = get_db_connection()
            c = conn.cursor()
            c.execute('''
                INSERT INTO server_monitoring 
                (hostname, os, cpu_count, cpu_usage, memory_total, memory_used, memory_percent, 
                 disk_total, disk_used, disk_percent, open_ports, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                hostname,
                os_info,
                cpu_count,
                cpu_percent,
                round(memory.total / (1024**3), 2),
                round(memory.used / (1024**3), 2),
                memory.percent,
                round(disk.total / (1024**3), 2),
                round(disk.used / (1024**3), 2),
                round((disk.used / disk.total) * 100, 2),
                ','.join(map(str, open_ports)),
                'online'
            ))
            conn.commit()
            conn.close()

            server_info = {
                "hostname": hostname,
                "os": os_info,
                "cpu_count": cpu_count,
                "cpu_usage": f"{cpu_percent}%",
                "memory_total": f"{round(memory.total / (1024**3),2)} GB",
                "memory_used": f"{round(memory.used / (1024**3),2)} GB",
                "memory_percent": f"{memory.percent}%",
                "disk_total": f"{round(disk.total / (1024**3), 2)} GB",
                "disk_used": f"{round(disk.used / (1024**3), 2)} GB",
                "disk_percent": f"{round((disk.used / disk.total) * 100, 2)}%",
                "open_ports": open_ports
            }
        except Exception as e:
            server_info = {"error": f"server_info_failure: {type(e).__name__}: {e} | trace: {traceback.format_exc()}"}
    else:
        server_info = None

    # Load and ping servers
    conn = get_db_connection()
    c = conn.cursor()
    base_sql = "SELECT id, name, ip_address, location, alive, last_ping_at FROM servers"
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY name"
    c.execute(base_sql, params)
    servers = c.fetchall()

    for s in servers:
        ip = s["ip_address"]
        count_flag = '-n' if platform.system().lower().startswith('win') else '-c'
        try:
            result = subprocess.run(['ping', count_flag, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            alive = 1 if result.returncode == 0 else 0
        except Exception:
            alive = 0
        now_dt = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
        try:
            c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (alive, now_dt, s["id"]))
        except Exception:
            pass
    conn.commit()

    c.execute(base_sql, params)
    servers = c.fetchall()
    conn.close()

    return render_template('server.html', server_info=server_info, servers=servers, locations=get_locations(), user=user)

@app.route('/server/ping/<int:server_id>')
@login_required
def ping_server(server_id):
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, ip_address, location FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Server not found.", "danger")
        return redirect(url_for('server'))
    if not user_can_access_location(user, row["location"]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('server'))

    ip = row["ip_address"]
    # Use helper
    alive = 1 if ping_host(ip, timeout_seconds=3) else 0

    now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (alive, now, server_id))
    conn.commit()
    conn.close()
    flash(f"Ping {'success' if alive else 'failed'} for {ip}.", "info")
    return redirect(url_for('server'))

@app.route('/server/delete/<int:server_id>', methods=['POST'])
@login_required
@rbac_write_required
def delete_server(server_id):
    """Delete a server by ID with RBAC location checks"""
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, location FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Server not found.", "danger")
        return redirect(url_for('server'))
    # RBAC: Admin/Analytics limited to their location
    if not user_can_access_location(user, row["location"]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('server'))
    try:
        c.execute("DELETE FROM servers WHERE id=?", (server_id,))
        conn.commit()
        flash(f"Deleted server '{row['name']}'.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to delete server: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('server'))

@app.route('/api/servers/status')
@login_required
def api_servers_status():
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    base_sql = "SELECT id, name, ip_address, location, alive, last_ping_at FROM servers"
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY name"
    c.execute(base_sql, params)
    servers = c.fetchall()

    count_flag = '-n' if platform.system().lower().startswith('win') else '-c'
    now_dt = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    statuses = []
    for s in servers:
        ip = s["ip_address"]
        try:
            result = subprocess.run(['ping', count_flag, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
            alive = 1 if result.returncode == 0 else 0
        except Exception:
            alive = 0
        try:
            c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (alive, now_dt, s["id"]))
        except Exception:
            pass
        statuses.append({
            "id": s["id"],
            "name": s["name"],
            "ip_address": s["ip_address"],
            "location": s["location"],
            "alive": bool(alive),
            "last_ping_at": now_dt
        })
    conn.commit()
    conn.close()
    return jsonify({"servers": statuses})

@app.route('/domain/delete/<path:domain_name>', methods=['POST'])
@login_required
@rbac_write_required
def delete_domain(domain_name):
    """Delete a domain by name along with its alerts, with RBAC location checks"""
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name, location FROM domains WHERE name=?", (domain_name,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Domain not found.", "danger")
        return redirect(url_for('domain'))
    if not user_can_access_location(user, row["location"]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('domain'))
    try:
        # Delete alerts first due to FK-like relationship
        c.execute("DELETE FROM domain_alerts WHERE domain_name=?", (row["name"],))
        c.execute("DELETE FROM domains WHERE name=?", (row["name"],))
        conn.commit()
        flash(f"Deleted domain '{row['name']}'.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to delete domain: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for('domain'))

@app.route('/server/history')
@login_required
def server_history():
    """Show server monitoring history"""
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get latest 50 records
    c.execute('''
        SELECT timestamp, hostname, os, cpu_count, cpu_usage, 
               memory_total, memory_used, memory_percent,
               disk_total, disk_used, disk_percent, open_ports, status
        FROM server_monitoring 
        ORDER BY timestamp DESC 
        LIMIT 50
    ''')
    
    history_records = c.fetchall()
    conn.close()
    
    return render_template('server_history.html', records=history_records)

# ---------- Server Metrics APIs ----------
@app.route('/api/server-metrics', methods=['GET'])
@login_required
def api_server_metrics():
    """Collect metrics for a server (local collection only) and persist to server_status.
    Query params: server_id (preferred) or ip
    Returns JSON with metrics or error.
    """
    user = get_current_user()
    server_id = request.args.get('server_id', type=int)
    ip = request.args.get('ip', type=str)

    if not server_id and not ip:
        return jsonify({"error": "server_id or ip is required"}), 400

    conn = get_db_connection()
    c = conn.cursor()
    row = None
    if server_id:
        c.execute("SELECT id, name, ip_address, location FROM servers WHERE id=?", (server_id,))
        row = c.fetchone()
    elif ip:
        c.execute("SELECT id, name, ip_address, location FROM servers WHERE ip_address=?", (ip,))
        row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"error": "server not found"}), 404

    # RBAC: Admin/Analytics limited to their location
    if not user_can_access_location(user, row["location"]):
        conn.close()
        return jsonify({"error": "access denied for this location"}), 403

    # Only collect metrics from local host. If target is not the current machine, return error.
    target_ip = row["ip_address"]
    local_hostnames = {platform.node().lower(), socket.gethostname().lower()}
    local_ips = {"127.0.0.1", "::1"}
    # Attempt to add local network IPs
    try:
        local_ips.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass

    if target_ip not in local_ips and target_ip.lower() not in local_hostnames:
        conn.close()
        return jsonify({"error": "remote collection not supported from this node"}), 502

    try:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        # Resolve disk root like earlier logic
        try:
            disk_root = os.environ.get("DISK_ROOT") or os.getenv('SystemDrive') or os.path.abspath(os.sep)
            if isinstance(disk_root, bytes):
                disk_root = disk_root.decode('utf-8', 'ignore')
            disk_root = (disk_root or '').strip()
            if platform.system().lower().startswith('win') and len(disk_root) == 2 and disk_root[1] == ':':
                disk_root = disk_root + '\\'
            disk_root = os.path.normpath(disk_root)
            if not os.path.isabs(disk_root):
                disk_root = os.path.abspath(disk_root)
            disk_usage = psutil.disk_usage(disk_root)
        except Exception:
            disk_usage = psutil.disk_usage(os.path.abspath(os.sep))

        total_disk_gb = round(disk_usage.total / (1024**3), 2)
        used_disk_gb = round(disk_usage.used / (1024**3), 2)
        disk_percent = round((disk_usage.used / disk_usage.total) * 100, 2) if disk_usage.total else 0.0

        now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
        c.execute(
            """
            INSERT INTO server_status (server_id, cpu_usage, memory_usage, total_disk, used_disk, disk_percent, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (row["id"], cpu_usage, mem.percent, total_disk_gb, used_disk_gb, disk_percent, now)
        )
        conn.commit()
        resp = {
            "server_id": row["id"],
            "name": row["name"],
            "ip_address": row["ip_address"],
            "cpu_usage": cpu_usage,
            "memory_usage": mem.percent,
            "total_disk": total_disk_gb,
            "used_disk": used_disk_gb,
            "disk_percent": disk_percent,
            "last_updated": now,
        }
        conn.close()
        return jsonify(resp)
    except Exception as e:
        conn.close()
        return jsonify({"error": f"metrics_collection_failed: {type(e).__name__}: {e}"}), 500


@app.route('/api/server-status/latest')
@login_required
def api_server_status_latest():
    """Return latest server_status per server, with RBAC filtering."""
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    # Base: latest status per server
    base_sql = """
        SELECT s.id as server_id, s.name, s.ip_address, s.location,
               st.cpu_usage, st.memory_usage, st.total_disk, st.used_disk, st.disk_percent, st.last_updated
        FROM servers s
        LEFT JOIN (
            SELECT t1.* FROM server_status t1
            JOIN (
                SELECT server_id, MAX(last_updated) as max_ts
                FROM server_status
                GROUP BY server_id
            ) t2 ON t1.server_id = t2.server_id AND t1.last_updated = t2.max_ts
        ) st ON st.server_id = s.id
    """
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(s.location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY s.name"
    c.execute(base_sql, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"server_status": rows})

# ---------- Server Alerts APIs & Watcher ----------

def is_valid_email(email: str) -> bool:
    if not email:
        return False
    return "@" in email and "." in email

@app.route('/api/server-alerts/<int:server_id>', methods=['GET'])
@login_required
def api_list_server_alerts(server_id):
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, location FROM servers WHERE id=?", (server_id,))
    s = c.fetchone()
    if not s:
        conn.close()
        return jsonify({"error": "server not found"}), 404
    if not user_can_access_location(user, s["location"]):
        conn.close()
        return jsonify({"error": "access denied"}), 403
    c.execute("SELECT email_address, last_alert_sent FROM server_alerts WHERE server_id=? ORDER BY email_address", (server_id,))
    rows = [{"email": r[0], "last_alert_sent": r[1]} for r in c.fetchall()]
    conn.close()
    return jsonify({"server_id": server_id, "emails": rows})

@app.route('/api/server-alerts/<int:server_id>', methods=['POST'])
@login_required
@rbac_write_required
def api_add_server_alert_email(server_id):
    user = get_current_user()
    email = (request.form.get('email') or request.json.get('email') if request.is_json else request.form.get('email')) if request else None
    email = (email or '').strip().lower()
    if not is_valid_email(email):
        return jsonify({"error": "invalid email"}), 400
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT location FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "server not found"}), 404
    if not user_can_access_location(user, row["location"]):
        conn.close()
        return jsonify({"error": "access denied"}), 403
    try:
        c.execute("INSERT OR IGNORE INTO server_alerts(server_id, email_address) VALUES(?, ?)", (server_id, email))
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/server-alerts/<int:server_id>/delete', methods=['POST'])
@login_required
@rbac_write_required
def api_delete_server_alert_email(server_id):
    user = get_current_user()
    email = (request.form.get('email') or request.json.get('email') if request.is_json else request.form.get('email')) if request else None
    email = (email or '').strip().lower()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT location FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "server not found"}), 404
    if not user_can_access_location(user, row["location"]):
        conn.close()
        return jsonify({"error": "access denied"}), 403
    try:
        c.execute("DELETE FROM server_alerts WHERE server_id=? AND email_address=?", (server_id, email))
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({"error": str(e)}), 500

# Background watcher for offline/online alerts
_watcher_thread_started = False
_prev_offline = {}
_pinger_thread_started = False
_ping_failures = {}
_ping_successes = {}

def _send_server_email(recipients, subject, body):
    return send_email_smtp(recipients, subject, body)

def _format_server_summary(s):
    return f"Server: {s['name']} (IP: {s['ip_address']}, Location: {s['location']})"

def _watch_servers_and_alert(interval_seconds=60, repeat_minutes=5, send_recovery=True):
    global _prev_offline
    while True:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            # Get servers and their alert emails
            c.execute("SELECT id, name, ip_address, location, alive FROM servers")
            servers = [dict(r) for r in c.fetchall()]

            now = datetime.datetime.now()
            for s in servers:
                sid = s['id']
                offline = not bool(s.get('alive', 0))
                # Load alert emails
                c.execute("SELECT email_address, last_alert_sent FROM server_alerts WHERE server_id=?", (sid,))
                alerts = c.fetchall()
                if offline:
                    # Immediate and repeated alerts
                    for a in alerts:
                        email = a[0]
                        last_sent = a[1]
                        should_send = False
                        if not last_sent:
                            should_send = True
                        else:
                            try:
                                last_dt = datetime.datetime.fromisoformat(last_sent)
                            except Exception:
                                last_dt = None
                            if not last_dt or (now - last_dt).total_seconds() >= repeat_minutes * 60:
                                should_send = True
                        if should_send:
                            subject = f"[ALERT] Server OFFLINE: {s['name']}"
                            body = _format_server_summary(s) + f"\nStatus: Offline\nTimestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}\nServer has gone offline."
                            ok, err = _send_server_email(email, subject, body)
                            if ok:
                                c.execute("UPDATE server_alerts SET last_alert_sent=? WHERE server_id=? AND email_address=?", (now.isoformat(sep=' ', timespec='seconds'), sid, email))
                                conn.commit()
                    _prev_offline[sid] = True
                else:
                    # Recovery path if previously offline
                    if _prev_offline.get(sid) and send_recovery and alerts:
                        subject = f"[RECOVERY] Server ONLINE: {s['name']}"
                        body = _format_server_summary(s) + f"\nStatus: Online\nTimestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}\nServer is back online."
                        for a in alerts:
                            email = a[0]
                            _send_server_email(email, subject, body)
                        # Reset last_alert_sent to allow fresh cycles on next offline
                        c.execute("UPDATE server_alerts SET last_alert_sent=NULL WHERE server_id=?", (sid,))
                        conn.commit()
                    _prev_offline[sid] = False

            conn.close()
        except Exception as e:
            # Avoid crashing the watcher
            print("[watcher] error:", e)
        time.sleep(interval_seconds)

def _start_watcher_once():
    global _watcher_thread_started, _pinger_thread_started
    # Avoid double start under Flask reloader
    if os.environ.get('WERKZEUG_RUN_MAIN') not in ('true', 'True') and app.debug:
        return
    if not _watcher_thread_started:
        t = threading.Thread(target=_watch_servers_and_alert, kwargs={"interval_seconds": 60, "repeat_minutes": 5, "send_recovery": True}, daemon=True)
        t.start()
        _watcher_thread_started = True
    if not _pinger_thread_started:
        p = threading.Thread(target=_background_ping_loop, kwargs={"interval_seconds": 3}, daemon=True)
        p.start()
        _pinger_thread_started = True

def _background_ping_loop(interval_seconds=10):
    while True:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT id, ip_address FROM servers")
            rows = c.fetchall()
            now_dt = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
            for r in rows:
                sid = r["id"]
                ip = r["ip_address"]
                result_alive = 1 if ping_host(ip, timeout_seconds=1) else 0
                # Get current known state from DB
                try:
                    c.execute("SELECT alive FROM servers WHERE id=?", (sid,))
                    row_state = c.fetchone()
                    current_alive = int(row_state[0] or 0) if row_state is not None else 0
                except Exception:
                    current_alive = 0

                # Hysteresis: require 2 consecutive opposite results to flip
                changed = False
                if current_alive == 1:
                    if result_alive == 1:
                        _ping_failures[sid] = 0
                    else:
                        _ping_failures[sid] = _ping_failures.get(sid, 0) + 1
                        if _ping_failures[sid] >= 2:
                            current_alive = 0
                            _ping_failures[sid] = 0
                            _ping_successes[sid] = 0
                            changed = True
                else:  # currently offline
                    if result_alive == 0:
                        _ping_successes[sid] = 0
                    else:
                        _ping_successes[sid] = _ping_successes.get(sid, 0) + 1
                        if _ping_successes[sid] >= 2:
                            current_alive = 1
                            _ping_successes[sid] = 0
                            _ping_failures[sid] = 0
                            changed = True

                # Always update last_ping_at, and alive only if changed
                if changed:
                    try:
                        c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (current_alive, now_dt, sid))
                    except Exception:
                        pass
                else:
                    try:
                        c.execute("UPDATE servers SET last_ping_at=? WHERE id=?", (now_dt, sid))
                    except Exception:
                        pass
            conn.commit()
            conn.close()
        except Exception as e:
            print("[pinger] error:", e)
        time.sleep(interval_seconds)

if __name__ == '__main__':
    _start_watcher_once()
    # Prevent double threads: rely on WERKZEUG_RUN_MAIN guard in _start_watcher_once
    app.run(debug=True, host='0.0.0.0', port=5000)

