from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import ssl, socket, datetime, whois, platform, psutil, sqlite3, smtplib, subprocess, functools, os, traceback
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
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'POST':
        if is_read_only(user):
            flash("You have read-only access.", "warning")
            return redirect(url_for('server'))
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
    try:
        hostname = platform.node()
        os_info = f"{platform.system()} {platform.release()}"
        cpu_count = psutil.cpu_count(logical=True)
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        # Resolve a clean disk root path with multiple layers of safety
        try:
            # 1) Allow override via env
            disk_root = os.environ.get("DISK_ROOT")
            # 2) Else prefer Windows system drive, else fallback to '/'
            if not disk_root:
                sys_drive = os.getenv('SystemDrive')  # e.g. 'C:'
                if sys_drive:
                    disk_root = sys_drive
                else:
                    disk_root = os.path.abspath(os.sep)

            # Ensure string type
            if isinstance(disk_root, bytes):
                disk_root = disk_root.decode('utf-8', 'ignore')
            # Strip and normalize
            disk_root = (disk_root or '').strip()
            if platform.system().lower().startswith('win'):
                # Ensure like 'C:\'
                if len(disk_root) == 2 and disk_root[1] == ':':
                    disk_root = disk_root + '\\'
            disk_root = os.path.normpath(disk_root)
            if not os.path.isabs(disk_root):
                disk_root = os.path.abspath(disk_root)

            # Debug prints (console) to verify value
            print("[server] disk_root=", repr(disk_root), type(disk_root))

            disk = psutil.disk_usage(disk_root)
        except Exception as disk_err:
            # Fallback to user's home directory
            try:
                fallback_root = os.path.expanduser('~')
                fallback_root = os.path.normpath(fallback_root)
                if not os.path.isabs(fallback_root):
                    fallback_root = os.path.abspath(fallback_root)
                print("[server] fallback_root=", repr(fallback_root), type(fallback_root))
                disk = psutil.disk_usage(fallback_root)
            except Exception as disk_err2:
                # Final fallback to OS root
                try:
                    final_root = os.path.abspath(os.sep)
                    print("[server] final_root=", repr(final_root), type(final_root))
                    disk = psutil.disk_usage(final_root)
                except Exception as disk_err3:
                    raise RuntimeError(
                        f"disk_usage_failed primary={repr(disk_root)} err={disk_err} "
                        f"fallback={repr(fallback_root) if 'fallback_root' in locals() else None} err2={disk_err2} "
                        f"final={repr(final_root) if 'final_root' in locals() else None} err3={disk_err3}"
                    )

        # Check common ports
        common_ports = [22, 80, 443]
        open_ports = []
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex(('127.0.0.1', port)) == 0:
                open_ports.append(port)
            sock.close()

        # Store current server stats in database
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
        # Provide detailed error with traceback to diagnose platform-specific issues
        server_info = {"error": f"server_info_failure: {type(e).__name__}: {e} | trace: {traceback.format_exc()}"}

    # Load servers list filtered by role/location
    base_sql = "SELECT id, name, ip_address, location, alive, last_ping_at FROM servers"
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY name"
    c.execute(base_sql, params)
    servers = c.fetchall()

    # Auto-ping servers to update alive status and last_ping_at
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

    # Re-fetch after updates for latest values
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
    # Cross-platform ping: Windows uses '-n 1', Linux/macOS use '-c 1'
    count_flag = '-n' if platform.system().lower().startswith('win') else '-c'
    try:
        result = subprocess.run(['ping', count_flag, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        alive = 1 if result.returncode == 0 else 0
    except Exception:
        alive = 0

    now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (alive, now, server_id))
    conn.commit()
    conn.close()
    flash(f"Ping {'success' if alive else 'failed'} for {ip}.", "info")
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

