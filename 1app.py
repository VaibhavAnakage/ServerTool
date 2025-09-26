from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import ssl, socket, datetime, whois, platform, psutil, sqlite3, smtplib, subprocess, functools, os, traceback, threading, time, collections
from email.message import EmailMessage

# Initialize Flask app early so decorators below have a defined app
try:
    app
except NameError:
    app = Flask(__name__)
    app.secret_key = os.environ.get('APP_SECRET', 'replace-with-your-secret')

# Ensure DB_FILE is available early for network helpers
DB_FILE = os.environ.get('MONITORING_DB_PATH', 'monitoring.db')

def net_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Provide get_db_connection early for modules that expect it
def get_db_connection():
    return net_db()

# ================= Network Monitoring =================
def ensure_network_schema():
    # Open DB directly to avoid ordering issues before get_db_connection/DB_FILE are defined
    conn = net_db()
    c = conn.cursor()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS network_device (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            manufacturer TEXT,
            added_at TEXT,
            enabled INTEGER DEFAULT 1,
            last_status TEXT,
            last_rtt_ms REAL,
            last_change_at TEXT,
            notes TEXT
        );
        CREATE TABLE IF NOT EXISTS network_check (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            status TEXT,
            detail_text TEXT,
            created_at TEXT,
            FOREIGN KEY(device_id) REFERENCES network_device(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS network_alert (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            kind TEXT,
            severity TEXT,
            message TEXT,
            created_at TEXT,
            sent_email INTEGER DEFAULT 0,
            FOREIGN KEY(device_id) REFERENCES network_device(id) ON DELETE CASCADE
        );
        """
    )
    # Add device_type column if not exists
    try:
        c.execute("ALTER TABLE network_device ADD COLUMN device_type TEXT")
    except Exception:
        pass
    conn.commit(); conn.close()

ensure_network_schema()

def _run_cmd(cmd, timeout=20):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.returncode, out.stdout.strip(), out.stderr.strip()
    except Exception as e:
        return -1, "", str(e)

def _ping_ip(ip: str, count: int = 4):
    # Windows ping: -n, Linux: -c
    count_flag = '-n' if platform.system().lower().startswith('win') else '-c'
    rc, out, err = _run_cmd(['ping', count_flag, str(max(1, count)), ip], timeout=15)
    status = 'Alive' if rc == 0 else 'Down'
    # Try parse average RTT from output
    rtt = None
    for line in out.splitlines():
        if 'Average' in line or 'avg' in line.lower():
            # Windows: Average = 12ms; Linux: rtt min/avg/max
            # Try extract number before 'ms'
            import re
            m = re.search(r"(Average|avg)[^0-9]*([0-9]+\.?[0-9]*)\s*ms", line, re.I)
            if not m:
                m = re.search(r"=\s*([0-9\.]+)/([0-9\.]+)/", line)  # linux avg is group(2)
                if m:
                    try:
                        rtt = float(m.group(2))
                    except: pass
            else:
                try:
                    rtt = float(m.group(2))
                except: pass
    return status, rtt, (out or err)

def _traceroute(ip: str):
    cmd = ['tracert', ip] if platform.system().lower().startswith('win') else ['traceroute', ip]
    return _run_cmd(cmd, timeout=60)

def _nmap_scan(ip: str):
    return _run_cmd(['nmap', '-sS', '-sV', ip], timeout=90)

def _nmap_os(ip: str):
    return _run_cmd(['nmap', '-O', ip], timeout=90)

def _curl_headers(ip: str):
    return _run_cmd(['curl', '-I', f'http://{ip}'], timeout=20)

def _openssl_tls(ip: str):
    return _run_cmd(['openssl', 's_client', '-connect', f'{ip}:443', '-servername', ip], timeout=20)

def _snmp_walk(ip: str, community: str):
    return _run_cmd(['snmpwalk', '-v2c', '-c', community, ip], timeout=60)

def _resolve_mac_and_vendor(ip: str):
    # Best-effort ARP
    rc, out, err = _run_cmd(['arp', '-a', ip], timeout=10)
    mac = None
    if out:
        import re
        m = re.search(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", out)
        if m:
            mac = m.group(0)
    vendor = None
    # If we have a MAC, try macvendors API via curl
    if mac:
        rc2, out2, err2 = _run_cmd(['curl', '-s', f'https://api.macvendors.com/{mac}'], timeout=10)
        if rc2 == 0 and out2:
            vendor = out2.strip()[:200]
    return mac, vendor

def _network_alert(conn, device_id: int, message: str, severity='critical', kind='status'):
    c = conn.cursor()
    now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    c.execute("INSERT INTO network_alert(device_id,kind,severity,message,created_at) VALUES(?,?,?,?,?)",
              (device_id, kind, severity, message, now))
    conn.commit()
    # Optionally send email if SMTP configured
    try:
        send_simple_email(f"Network Alert: Device {device_id}", message)
        c.execute("UPDATE network_alert SET sent_email=1 WHERE id = last_insert_rowid()")
        conn.commit()
    except Exception:
        pass

def send_simple_email(subject: str, body: str):
    # Minimal helper using SMTP config placeholders if set
    smtp_host = os.environ.get('SMTP_HOST')
    smtp_user = os.environ.get('SMTP_USER')
    smtp_pass = os.environ.get('SMTP_PASS')
    to_addr = os.environ.get('ALERT_EMAIL_TO')
    if not (smtp_host and smtp_user and smtp_pass and to_addr):
        return
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_addr
    msg.set_content(body)
    with smtplib.SMTP(smtp_host) as s:
        s.starttls()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)

# Background monitor: ping devices every 60s
def _network_monitor_loop():
    while True:
        try:
            conn = net_db(); c = conn.cursor()
            c.execute("SELECT id, ip, enabled, last_status, last_rtt_ms, mac, manufacturer FROM network_device WHERE enabled=1")
            for did, ip, enabled, last_status, last_rtt, mac, manufacturer in c.fetchall():
                status, rtt, detail = _ping_ip(ip, count=1)
                now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
                c.execute("INSERT INTO network_check(device_id,kind,status,detail_text,created_at) VALUES(?,?,?,?,?)",
                          (did, 'ping', status, detail, now))
                # Detect changes
                if last_status != status:
                    _network_alert(conn, did, f"Device {ip} changed status: {last_status} -> {status}")
                    c.execute("UPDATE network_device SET last_status=?, last_rtt_ms=?, last_change_at=? WHERE id=?",
                              (status, rtt, now, did))
                else:
                    c.execute("UPDATE network_device SET last_status=?, last_rtt_ms=? WHERE id=?",
                              (status, rtt, did))
                # Enrich missing MAC/vendor opportunistically
                if not mac or not manufacturer:
                    new_mac, new_vendor = _resolve_mac_and_vendor(ip)
                    if new_mac or new_vendor:
                        c.execute("UPDATE network_device SET mac=COALESCE(?, mac), manufacturer=COALESCE(?, manufacturer) WHERE id=?",
                                  (new_mac, new_vendor, did))
            conn.commit(); conn.close()
        except Exception:
            traceback.print_exc()
        time.sleep(8)

# Start monitor thread
try:
    t = threading.Thread(target=_network_monitor_loop, daemon=True)
    t.start()
except Exception:
    pass

@app.route('/network')
def network_page():
    user = get_current_user()
    return render_template('network.html', user=user)

@app.route('/api/network/devices', methods=['GET', 'POST'])
def api_network_devices():
    if request.method == 'POST':
        ip = request.form.get('ip') or (request.json and request.json.get('ip'))
        device_type = request.form.get('device_type') or (request.json and request.json.get('device_type'))
        if not ip:
            return jsonify({"error": "ip required"}), 400
        mac, vendor = _resolve_mac_and_vendor(ip)
        now = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
        conn = get_db_connection(); c = conn.cursor()
        try:
            c.execute("INSERT INTO network_device(ip, mac, manufacturer, added_at, enabled, device_type) VALUES(?,?,?,?,1,?)",
                      (ip, mac, vendor, now, device_type))
            conn.commit()
            return jsonify({"ok": True}), 201
        except sqlite3.IntegrityError:
            return jsonify({"ok": True, "note": "already exists"})
        finally:
            conn.close()
    # GET list
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT id, ip, mac, manufacturer, device_type, enabled, last_status, last_rtt_ms, last_change_at FROM network_device ORDER BY ip")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({"devices": rows})

@app.route('/api/network/device/<int:device_id>/checks')
def api_network_device_checks(device_id: int):
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT kind, status, created_at FROM network_check WHERE device_id=? ORDER BY created_at DESC LIMIT 50", (device_id,))
    out = [dict(r) for r in c.fetchall()]
    conn.close(); return jsonify({"checks": out})

@app.route('/api/network/device/<int:device_id>/action', methods=['POST'])
def api_network_device_action(device_id: int):
    action = request.form.get('action') or (request.json and request.json.get('action'))
    community = request.form.get('community') or (request.json and request.json.get('community')) or 'public'
    if not action:
        return jsonify({"error": "action required"}), 400
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT ip FROM network_device WHERE id=?", (device_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return jsonify({"error": "device not found"}), 404
    ip = row[0]
    # Dispatch
    if action == 'ping':
        status, rtt, detail = _ping_ip(ip)
        return jsonify({"action": action, "status": status, "rtt_ms": rtt, "output": detail})
    if action == 'traceroute':
        rc, out, err = _traceroute(ip); return jsonify({"action": action, "rc": rc, "output": out or err})
    if action == 'nmap':
        rc, out, err = _nmap_scan(ip); return jsonify({"action": action, "rc": rc, "output": out or err})
    if action == 'os_fingerprint':
        rc, out, err = _nmap_os(ip); return jsonify({"action": action, "rc": rc, "output": out or err})
    if action == 'http_headers':
        rc, out, err = _curl_headers(ip); return jsonify({"action": action, "rc": rc, "output": out or err})
    if action == 'tls_info':
        rc, out, err = _openssl_tls(ip); return jsonify({"action": action, "rc": rc, "output": out or err})
    if action == 'snmp':
        rc, out, err = _snmp_walk(ip, community); return jsonify({"action": action, "rc": rc, "output": out or err})
    if action == 'resolve_vendor':
        new_mac, new_vendor = _resolve_mac_and_vendor(ip)
        conn = get_db_connection(); c = conn.cursor()
        if new_mac or new_vendor:
            c.execute("UPDATE network_device SET mac=COALESCE(?, mac), manufacturer=COALESCE(?, manufacturer) WHERE id=?",
                      (new_mac, new_vendor, device_id))
            conn.commit()
        c.execute("SELECT mac, manufacturer FROM network_device WHERE id=?", (device_id,))
        row = c.fetchone(); conn.close()
        return jsonify({"action": action, "mac": row[0] if row else new_mac, "manufacturer": row[1] if row else new_vendor})
    return jsonify({"error": "unknown action"}), 400

@app.route('/api/network/alerts')
def api_network_alerts():
    limit = max(1, min(200, request.args.get('limit', type=int) or 50))
    conn = get_db_connection(); c = conn.cursor()
    c.execute(
        """
        SELECT a.created_at, d.ip, a.severity, a.message
        FROM network_alert a
        JOIN network_device d ON d.id = a.device_id
        ORDER BY a.created_at DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = [dict(r) for r in c.fetchall()]
    conn.close();
    return jsonify({"alerts": rows})
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import ssl, socket, datetime, whois, platform, psutil, sqlite3, smtplib, subprocess, functools, os, traceback, threading, time, collections
from email.message import EmailMessage

# app was initialized earlier to avoid decorator NameError; do not re-initialize here
# app = Flask(__name__)
# app.secret_key = "replace-with-your-secret"  # for flash messages
DB_FILE = os.environ.get('MONITORING_DB_PATH', 'monitoring.db')
ACTIVE_PING_ENABLED = os.environ.get('ACTIVE_PING_ENABLED', '0') == '1'
GLOBAL_INGEST_LOCK = threading.Lock()
INGEST_QUEUE = collections.deque(maxlen=10000)
INGEST_EVENT = threading.Event()
INGEST_STATS = {
    'enqueued': 0,
    'processed': 0,
    'errors': 0,
    'last_error': None,
}

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
    # Increase timeout to wait for locks; allow cross-thread usage; row_factory for dict-like rows
    conn = sqlite3.connect(DB_FILE, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        # Busy timeout at the connection level as well (ms)
        conn.execute("PRAGMA busy_timeout = 15000")
    except Exception:
        pass
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

# ---------- Ping Logs Helpers ----------
LOGS_DIR = os.path.join(os.path.dirname(__file__), 'logs', 'txtx')
PING_LOG_FILE = os.path.join(LOGS_DIR, 'ping_logs.txt')

def ensure_ping_logs_dir():
    try:
        os.makedirs(LOGS_DIR, exist_ok=True)
        # ensure the file exists
        if not os.path.exists(PING_LOG_FILE):
            with open(PING_LOG_FILE, 'a', encoding='utf-8') as f:
                f.write('')
    except Exception:
        pass

def write_ping_log(ip: str, alive: bool, source: str, server_id=None, name=None):
    """Append a single ping event to the ping logs file.
    Format: ISO_TIME | SOURCE | SERVER_ID | NAME | IP | STATUS
    """
    try:
        ensure_ping_logs_dir()
        ts = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
        status = 'ONLINE' if alive else 'OFFLINE'
        sid = str(server_id) if server_id is not None else '-'
        sname = name or '-'
        line = f"{ts} | {source} | {sid} | {sname} | {ip} | {status}\n"
        with open(PING_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        # swallow logging errors to not affect app flow
        pass

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
    # Ensure unique index to prevent duplicate inserts for the same timestamp per server
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_server_status_server_ts ON server_status(server_id, last_updated)")
    except Exception:
        pass
    conn.commit()
    conn.close()

ensure_server_status_schema()

# Windows-specific server status schema
def ensure_server_status_windows_schema():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS server_status_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id INTEGER NOT NULL,
            cpu_usage REAL,
            memory_usage REAL,
            total_drives INTEGER,
            c_total_gb REAL,
            c_used_gb REAL,
            c_percent REAL,
            last_updated TEXT,
            FOREIGN KEY(server_id) REFERENCES servers(id)
        )
        """
    )
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_server_status_win_server_ts ON server_status_windows(server_id, last_updated)")
    except Exception:
        pass
    conn.commit()
    conn.close()

ensure_server_status_windows_schema()

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

# Extra indices to speed up lookups and latest queries
def ensure_performance_indices():
    try:
        conn = get_db_connection(); c = conn.cursor()
        # For resolving servers quickly by (name, ip_address)
        c.execute("CREATE INDEX IF NOT EXISTS ix_servers_name_ip ON servers(name, ip_address)")
        # For latest status queries by server
        c.execute("CREATE INDEX IF NOT EXISTS ix_server_status_server ON server_status(server_id)")
        conn.commit(); conn.close()
    except Exception:
        pass

ensure_performance_indices()

# Apply global PRAGMAs (WAL, synchronous normal) once
def ensure_sqlite_pragmas():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        # WAL mode allows one writer with many readers and reduces lock contention
        c.execute("PRAGMA journal_mode = WAL")
        # Reasonable durability with better concurrency
        c.execute("PRAGMA synchronous = NORMAL")
        # Connection-level busy timeout already set, but set database default too
        c.execute("PRAGMA busy_timeout = 15000")
        conn.commit()
        conn.close()
    except Exception:
        pass

ensure_sqlite_pragmas()

# ---------- Ingestion Worker ----------
def _ingest_write_once(task):
    """Write a single metrics task to DB with minimal locking. Supports linux/windows kinds."""
    server_id = task['server_id']
    ts = task['ts']
    kind = task.get('kind', 'linux')
    conn = get_db_connection(); c = conn.cursor()
    try:
        with GLOBAL_INGEST_LOCK:
            if kind == 'windows':
                c.execute(
                    """
                    INSERT OR IGNORE INTO server_status_windows (server_id, cpu_usage, memory_usage, total_drives, c_total_gb, c_used_gb, c_percent, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        server_id,
                        task.get('cpu_usage'),
                        task.get('memory_usage'),
                        task.get('total_drives'),
                        task.get('c_total_gb'),
                        task.get('c_used_gb'),
                        task.get('c_percent'),
                        ts,
                    )
                )
            else:
                c.execute(
                    """
                    INSERT OR IGNORE INTO server_status (server_id, cpu_usage, memory_usage, total_disk, used_disk, disk_percent, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        server_id,
                        task.get('cpu_usage'),
                        task.get('memory_usage'),
                        task.get('total_disk'),
                        task.get('used_disk'),
                        task.get('disk_percent'),
                        ts,
                    )
                )
            c.execute("UPDATE servers SET alive=1, last_ping_at=? WHERE id=?", (ts, server_id))
            conn.commit()
    finally:
        conn.close()
    # Log successful write for visibility
    try:
        print(f"[ingest] wrote kind={kind} server_id={server_id} ts={ts}")
        INGEST_STATS['processed'] += 1
    except Exception:
        pass

def ingest_worker():
    """Background worker to serialize DB writes from the ingestion endpoint."""
    while True:
        # Wait until there is work
        INGEST_EVENT.wait(timeout=1.0)
        try:
            while True:
                try:
                    task = INGEST_QUEUE.popleft()
                except IndexError:
                    # No more tasks; clear event and break
                    INGEST_EVENT.clear()
                    break
                # Retry a few times on locked
                attempts = 0
                backoff = 0.05
                while True:
                    attempts += 1
                    try:
                        _ingest_write_once(task)
                        break
                    except sqlite3.OperationalError as e:
                        if 'locked' in str(e).lower() or 'busy' in str(e).lower():
                            time.sleep(min(0.5, backoff * attempts))
                            continue
                        else:
                            # Drop this task but do not crash worker
                            try:
                                INGEST_STATS['errors'] += 1
                                INGEST_STATS['last_error'] = f"OperationalError: {e}"
                                print(f"[ingest] error: {e}")
                            except Exception:
                                pass
                            break
                    except Exception as e:
                        # Catch-all to avoid worker death
                        try:
                            INGEST_STATS['errors'] += 1
                            INGEST_STATS['last_error'] = f"{type(e).__name__}: {e}"
                            print(f"[ingest] unexpected error: {type(e).__name__}: {e}")
                        except Exception:
                            pass
                        break
        except Exception:
            # Never let the worker die
            time.sleep(0.1)

# Start worker thread (daemon) only in the active reloader process
try:
    # When using Flask debug reloader, this env var is 'true' in the child process that serves requests
    if os.environ.get('WERKZEUG_RUN_MAIN', 'true').lower() == 'true':
        _t = threading.Thread(target=ingest_worker, name='ingest-worker', daemon=True)
        _t.start()
        print('[ingest] worker started')
except Exception as _e:
    print(f'[ingest] worker failed to start: {_e}')

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

def super_admin_required(view_func):
    @functools.wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for('login'))
        if (user["role"] or "").lower() != "super_admin":
            flash("Only super admin can access this page.", "danger")
            return redirect(url_for('index'))
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

# ---------- API Basic Auth Helpers ----------
def require_basic_auth_api():
    """Validate HTTP Basic Auth against users table for role='api'.
    Returns (ok, result). If ok is True, result is the user row; otherwise, result is a Flask response (401).
    """
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        resp = jsonify({"error": "authentication required"})
        resp.status_code = 401
        resp.headers['WWW-Authenticate'] = 'Basic realm="Metrics API"'
        return False, resp
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash, role FROM users WHERE email = ? AND LOWER(role)='api'", (auth.username.strip().lower(),))
    row = c.fetchone()
    conn.close()
    if not row:
        resp = jsonify({"error": "invalid credentials"})
        resp.status_code = 401
        resp.headers['WWW-Authenticate'] = 'Basic realm="Metrics API"'
        return False, resp
    from werkzeug.security import check_password_hash
    if not check_password_hash(row["password_hash"], auth.password):
        resp = jsonify({"error": "invalid credentials"})
        resp.status_code = 401
        resp.headers['WWW-Authenticate'] = 'Basic realm="Metrics API"'
        return False, resp
    return True, row

def ensure_api_user_seed():
    """Optionally seed an API user from env vars.
    Set API_INGEST_EMAIL and API_INGEST_PASSWORD to auto-create/update the API user.
    """
    email = (os.environ.get('API_INGEST_EMAIL') or '').strip().lower()
    password = os.environ.get('API_INGEST_PASSWORD')
    if not email or not password:
        return
    try:
        from werkzeug.security import generate_password_hash
        pw_hash = generate_password_hash(password)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        existing = c.fetchone()
        if existing:
            c.execute("UPDATE users SET password_hash=?, role='api', location=NULL, name=COALESCE(name,'API User') WHERE email=?", (pw_hash, email))
        else:
            c.execute("INSERT INTO users(name, email, password_hash, role, location) VALUES(?, ?, ?, 'api', NULL)", ("API User", email, pw_hash))
        conn.commit()
        conn.close()
    except Exception:
        pass

# ---------- Auth Routes ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash, role FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    from werkzeug.security import check_password_hash
    if row and check_password_hash(row["password_hash"], password):
        # Disallow API user from portal login
        if (row["role"] or '').lower() == 'api':
            flash("API user cannot log into the portal.", "danger")
            return redirect(url_for('login'))
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

    # Load and conditionally ping servers (throttled)
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

    # Throttle to once per 60s
    now_dt = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    for s in servers:
        ip = s["ip_address"]
        last = (s["last_ping_at"] or "").strip() if isinstance(s["last_ping_at"], str) else (s["last_ping_at"] or "")
        should_ping = False
        if ACTIVE_PING_ENABLED:
            try:
                # Parse last_ping_at and check age
                fmt = "%Y-%m-%d %H:%M:%S"
                last_dt = datetime.datetime.strptime(last, fmt) if last else None
                age_ok = True if last_dt is None else (datetime.datetime.now() - last_dt).total_seconds() >= 60
                should_ping = age_ok
            except Exception:
                should_ping = True
        if should_ping:
            count_flag = '-n' if platform.system().lower().startswith('win') else '-c'
            alive = 0
            try:
                # Two attempts to reduce false negatives
                for _ in range(2):
                    result = subprocess.run(['ping', count_flag, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                    if result.returncode == 0:
                        alive = 1
                        break
            except Exception:
                alive = 0
            try:
                c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (alive, now_dt, s["id"]))
            except Exception:
                pass
            # log ping result
            try:
                write_ping_log(ip, bool(alive), source='server_view_refresh', server_id=s["id"], name=s["name"])
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
    c.execute("SELECT id, name, ip_address, location FROM servers WHERE id=?", (server_id,))
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
    # log ping result
    try:
        write_ping_log(ip, bool(alive), source='manual_ping', server_id=server_id, name=row["name"] if isinstance(row, (sqlite3.Row, dict)) and "name" in row.keys() else None)
    except Exception:
        pass
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

    now_dt = datetime.datetime.now().isoformat(sep=' ', timespec='seconds')
    statuses = []
    for s in servers:
        ip = s["ip_address"]
        last = (s["last_ping_at"] or "").strip() if isinstance(s["last_ping_at"], str) else (s["last_ping_at"] or "")
        do_ping = False
        if ACTIVE_PING_ENABLED:
            try:
                fmt = "%Y-%m-%d %H:%M:%S"
                last_dt = datetime.datetime.strptime(last, fmt) if last else None
                do_ping = True if last_dt is None else (datetime.datetime.now() - last_dt).total_seconds() >= 60
            except Exception:
                do_ping = True
        if do_ping:
            count_flag = '-n' if platform.system().lower().startswith('win') else '-c'
            alive = 0
            try:
                for _ in range(2):
                    result = subprocess.run(['ping', count_flag, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
                    if result.returncode == 0:
                        alive = 1
                        break
            except Exception:
                alive = 0
            try:
                c.execute("UPDATE servers SET alive=?, last_ping_at=? WHERE id=?", (alive, now_dt, s["id"]))
            except Exception:
                pass
            # log ping result
            try:
                write_ping_log(ip, bool(alive), source='api_servers_status', server_id=s["id"], name=s["name"])
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
        else:
            statuses.append({
                "id": s["id"],
                "name": s["name"],
                "ip_address": s["ip_address"],
                "location": s["location"],
                "alive": bool(s["alive"]),
                "last_ping_at": s["last_ping_at"]
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

# Ensure API user from environment (optional)
try:
    ensure_api_user_seed()
except Exception:
    pass

# ---------- Users Management (Super Admin only) ----------
@app.route('/users')
@login_required
@super_admin_required
def users_page():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, name, email, role, location FROM users ORDER BY name")
    rows = c.fetchall()
    conn.close()
    return render_template('users.html', users=rows, user=get_current_user())


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@super_admin_required
def create_user():
    if request.method == 'GET':
        # Allow preselecting role via query param, e.g. /users/create?role=api
        default_role = request.args.get('role', 'admin')
        form = {"role": default_role}
        return render_template('user_form.html', mode='create', locations=get_locations(), form=form, user=get_current_user())

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    role = request.form.get('role', '').strip()
    location = request.form.get('location', '').strip()
    password = request.form.get('password', '')

    if not name or not email or not role or not password:
        flash('Name, Email, Role and Password are required.', 'warning')
        return redirect(url_for('create_user'))

    if role in ('super_admin', 'api'):
        location = None

    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("SELECT 1 FROM users WHERE email=?", (email,))
        if c.fetchone():
            conn.close()
            flash('Email already exists.', 'danger')
            return redirect(url_for('create_user'))
        from werkzeug.security import generate_password_hash
        pw_hash = generate_password_hash(password)
        c.execute(
            "INSERT INTO users(name, email, password_hash, role, location) VALUES(?, ?, ?, ?, ?)",
            (name, email, pw_hash, role, location)
        )
        conn.commit()
        flash('User created.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Failed to create user: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('users_page'))


@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@super_admin_required
def edit_user(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    if request.method == 'GET':
        c.execute("SELECT id, name, email, role, location FROM users WHERE id=?", (user_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            flash('User not found.', 'danger')
            return redirect(url_for('users_page'))
        form = {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"], "location": row["location"]}
        return render_template('user_form.html', mode='edit', form=form, locations=get_locations(), user=get_current_user())

    # POST
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip().lower()
    role = request.form.get('role', '').strip()
    location = request.form.get('location', '').strip()
    password = request.form.get('password', '')

    if not name or not email or not role:
        conn.close()
        flash('Name, Email and Role are required.', 'warning')
        return redirect(url_for('edit_user', user_id=user_id))

    if role in ('super_admin', 'api'):
        location = None

    try:
        # Ensure email uniqueness for other users
        c.execute("SELECT id FROM users WHERE email=? AND id<>?", (email, user_id))
        if c.fetchone():
            conn.close()
            flash('Another user with this email already exists.', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))

        if password:
            from werkzeug.security import generate_password_hash
            pw_hash = generate_password_hash(password)
            c.execute("UPDATE users SET name=?, email=?, password_hash=?, role=?, location=? WHERE id=?",
                      (name, email, pw_hash, role, location, user_id))
        else:
            c.execute("UPDATE users SET name=?, email=?, role=?, location=? WHERE id=?",
                      (name, email, role, location, user_id))
        conn.commit()
        flash('User updated.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Failed to update user: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('users_page'))


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@super_admin_required
def delete_user(user_id):
    current = get_current_user()
    if current and current["id"] == user_id:
        flash('You cannot delete your own account while logged in.', 'warning')
        return redirect(url_for('users_page'))
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        flash('User deleted.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Failed to delete user: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('users_page'))

# ---------- Remote Metrics Ingestion (Basic Auth) ----------
@app.route('/api/ingest-metrics', methods=['POST'])
def api_ingest_metrics():
    t0 = time.time()
    ok, result = require_basic_auth_api()
    if not ok:
        return result
    t_auth = time.time()

    # Expect JSON body
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid json"}), 400

    if not isinstance(payload, dict):
        return jsonify({"error": "invalid payload"}), 400

    server_id = payload.get('server_id')
    name = payload.get('name')
    ip_address = payload.get('ip_address')
    cpu_usage = payload.get('cpu_usage')
    memory_usage = payload.get('memory_usage')
    total_disk = payload.get('total_disk')
    used_disk = payload.get('used_disk')
    disk_percent = payload.get('disk_percent')
    ts = payload.get('timestamp')

    if not (server_id or (name and ip_address)):
        return jsonify({"error": "server_id or (name and ip_address) required"}), 400

    # Resolve server using a short-lived connection
    row = None
    conn = get_db_connection(); c = conn.cursor()
    try:
        if server_id:
            try:
                c.execute("SELECT id, name FROM servers WHERE id=?", (int(server_id),))
                row = c.fetchone()
            except Exception:
                row = None
        if not row and name and ip_address:
            c.execute("SELECT id, name FROM servers WHERE name=? AND ip_address=?", (str(name).strip(), str(ip_address).strip()))
            row = c.fetchone()
        # If still not found, optionally auto-create a server record with empty location
        if not row and name and ip_address:
            try:
                c.execute("INSERT INTO servers(name, ip_address, location, alive, last_ping_at) VALUES(?, ?, ?, ?, ?)",
                          (str(name).strip(), str(ip_address).strip(), '', 1, datetime.datetime.now().isoformat(sep=' ', timespec='seconds')))
                conn.commit()
                c.execute("SELECT id, name FROM servers WHERE name=? AND ip_address=?", (str(name).strip(), str(ip_address).strip()))
                row = c.fetchone()
            except Exception:
                pass
    finally:
        conn.close()

    if not row:
        return jsonify({"error": "server not found"}), 404
    t_resolve = time.time()

    # Enqueue the write and return immediately (decouples clients from DB locks)
    # Always use server-side timestamp with milliseconds to avoid duplicate keys
    now = datetime.datetime.now().isoformat(sep=' ', timespec='milliseconds')
    # Determine ingestion kind: windows metrics if c_* fields present or os == 'windows'
    os_hint = str(payload.get('os') or payload.get('platform') or '').strip().lower()
    is_windows = os_hint == 'windows' or any(k in payload for k in ('c_total_gb','c_used_gb','c_percent','total_drives'))
    if is_windows:
        task = {
            'kind': 'windows',
            'server_id': row['id'],
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'total_drives': payload.get('total_drives'),
            'c_total_gb': payload.get('c_total_gb'),
            'c_used_gb': payload.get('c_used_gb'),
            'c_percent': payload.get('c_percent'),
            'ts': now,
        }
    else:
        task = {
            'kind': 'linux',
            'server_id': row['id'],
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'total_disk': total_disk,
            'used_disk': used_disk,
            'disk_percent': disk_percent,
            'ts': now,
        }
    try:
        INGEST_QUEUE.append(task)
        INGEST_EVENT.set()
        INGEST_STATS['enqueued'] += 1
    except Exception:
        return jsonify({"error": "queue_failed"}), 500

    t_done = time.time()
    print(f"[ingest] auth={t_auth-t0:.3f}s resolve={t_resolve-t_auth:.3f}s queued={(t_done-t_resolve):.3f}s total={t_done-t0:.3f}s")
    return jsonify({"ok": True, "queued": True, "server_id": row['id'], "name": row['name'], "saved_at": now}), 202

# ---------- Ingestion Health ----------
@app.route('/api/ingest-health')
def api_ingest_health():
    try:
        qlen = len(INGEST_QUEUE)
    except Exception:
        qlen = -1
    return jsonify({
        'queue_length': qlen,
        'stats': INGEST_STATS,
    })

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
        INNER JOIN (
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

# Time-series APIs for charts
@app.route('/api/server-status/history')
@login_required
def api_server_status_history():
    """Return time-series points (ts, cpu, mem) for Linux metrics for a server_id."""
    user = get_current_user()
    server_id = request.args.get('server_id', type=int)
    limit = request.args.get('limit', default=500, type=int)
    since_minutes = request.args.get('since_minutes', type=int)
    if not server_id:
        return jsonify({"error": "server_id required"}), 400
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT location FROM servers WHERE id=?", (server_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return jsonify({"error": "server not found"}), 404
    if not user_can_access_location(user, r[0]):
        conn.close(); return jsonify({"error": "access denied"}), 403
    sql = """
        SELECT last_updated, cpu_usage, memory_usage
        FROM server_status
        WHERE server_id=?
    """
    params = [server_id]
    if since_minutes is not None and since_minutes > 0:
        # Compute threshold timestamp in server format (seconds precision is fine)
        threshold = datetime.datetime.now() - datetime.timedelta(minutes=since_minutes)
        threshold_str = threshold.isoformat(sep=' ', timespec='seconds')
        sql += " AND last_updated >= ?"
        params.append(threshold_str)
    sql += " ORDER BY last_updated ASC LIMIT ?"
    params.append(max(1, min(5000, limit)))
    c.execute(sql, params)
    points = [{"ts": row[0], "cpu": row[1], "mem": row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify({"server_id": server_id, "points": points})

@app.route('/api/server-status/history-all')
@login_required
def api_server_status_history_all():
    """Return time-series for all accessible servers, combining Linux/Windows where available.
    Query params: since_minutes (optional), limit (default 500 per server)
    Output: { servers: [ {server_id, name, points:[{ts,cpu,mem}]} ] }
    """
    user = get_current_user()
    since_minutes = request.args.get('since_minutes', type=int)
    limit = request.args.get('limit', default=500, type=int)
    limit = max(50, min(5000, limit))

    conn = get_db_connection(); c = conn.cursor()
    base_sql = "SELECT id, name, location FROM servers"
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY name"
    c.execute(base_sql, params)
    servers = c.fetchall()

    # Build threshold
    threshold_str = None
    if since_minutes and since_minutes > 0:
        threshold = datetime.datetime.now() - datetime.timedelta(minutes=since_minutes)
        threshold_str = threshold.isoformat(sep=' ', timespec='seconds')

    out = []
    for s in servers:
        sid, name, loc = s[0], s[1], s[2]
        # Linux
        sql_l = "SELECT last_updated, cpu_usage, memory_usage FROM server_status WHERE server_id=?"
        params_l = [sid]
        if threshold_str:
            sql_l += " AND last_updated >= ?"
            params_l.append(threshold_str)
        sql_l += " ORDER BY last_updated ASC LIMIT ?"
        params_l.append(limit)
        c.execute(sql_l, params_l)
        lrows = c.fetchall()
        # Windows
        sql_w = "SELECT last_updated, cpu_usage, memory_usage FROM server_status_windows WHERE server_id=?"
        params_w = [sid]
        if threshold_str:
            sql_w += " AND last_updated >= ?"
            params_w.append(threshold_str)
        sql_w += " ORDER BY last_updated ASC LIMIT ?"
        params_w.append(limit)
        c.execute(sql_w, params_w)
        wrows = c.fetchall()

        # Merge by timestamp (string equality). If both present, prefer Windows values.
        m = {}
        for r in lrows:
            m[r[0]] = {"ts": r[0], "cpu": r[1], "mem": r[2]}
        for r in wrows:
            m[r[0]] = {"ts": r[0], "cpu": r[1], "mem": r[2]}
        points = [m[k] for k in sorted(m.keys())]
        if points:
            out.append({"server_id": sid, "name": name, "points": points})

    conn.close()
    return jsonify({"servers": out})

@app.route('/server/trends')
@login_required
def server_trends():
    """All servers CPU/Memory trends page."""
    user = get_current_user()
    return render_template('server_trends.html', user=user)

@app.route('/api/server-status/history-windows')
@login_required
def api_server_status_history_windows():
    """Return time-series points (ts, cpu, mem) for Windows metrics for a server_id."""
    user = get_current_user()
    server_id = request.args.get('server_id', type=int)
    limit = request.args.get('limit', default=500, type=int)
    since_minutes = request.args.get('since_minutes', type=int)
    if not server_id:
        return jsonify({"error": "server_id required"}), 400
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT location FROM servers WHERE id=?", (server_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return jsonify({"error": "server not found"}), 404
    if not user_can_access_location(user, r[0]):
        conn.close(); return jsonify({"error": "access denied"}), 403
    sql = """
        SELECT last_updated, cpu_usage, memory_usage
        FROM server_status_windows
        WHERE server_id=?
    """
    params = [server_id]
    if since_minutes is not None and since_minutes > 0:
        threshold = datetime.datetime.now() - datetime.timedelta(minutes=since_minutes)
        threshold_str = threshold.isoformat(sep=' ', timespec='seconds')
        sql += " AND last_updated >= ?"
        params.append(threshold_str)
    sql += " ORDER BY last_updated ASC LIMIT ?"
    params.append(max(1, min(5000, limit)))
    c.execute(sql, params)
    points = [{"ts": row[0], "cpu": row[1], "mem": row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify({"server_id": server_id, "points": points})

@app.route('/server/<int:server_id>')
@login_required
def server_detail(server_id):
    """Server detail page with info and CPU/memory graphs."""
    user = get_current_user()
    conn = get_db_connection(); c = conn.cursor()
    c.execute("SELECT id, name, ip_address, location, alive, last_ping_at FROM servers WHERE id=?", (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Server not found.", "danger")
        return redirect(url_for('server'))
    if not user_can_access_location(user, row[3]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('server'))
    info = {"id": row[0], "name": row[1], "ip_address": row[2], "location": row[3], "alive": bool(row[4]), "last_ping_at": row[5]}
    conn.close()
    return render_template('server_detail.html', server=info, user=user)

@app.route('/api/server-status/latest-windows')
@login_required
def api_server_status_latest_windows():
    """Return latest Windows server_status per server, with RBAC filtering."""
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    base_sql = """
        SELECT s.id as server_id, s.name, s.ip_address, s.location,
               st.cpu_usage, st.memory_usage, st.total_drives, st.c_total_gb, st.c_used_gb, st.c_percent, st.last_updated
        FROM servers s
        INNER JOIN (
            SELECT t1.* FROM server_status_windows t1
            JOIN (
                SELECT server_id, MAX(last_updated) as max_ts
                FROM server_status_windows
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

# ---------- Domain Security Monitoring ----------
def ensure_domain_security_schema():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS domain_security (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_name TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            summary_status TEXT,
            details_json TEXT
        )
        """
    )
    c.execute("CREATE INDEX IF NOT EXISTS idx_domain_security_domain_time ON domain_security(domain_name, scanned_at)")
    conn.commit()
    conn.close()

ensure_domain_security_schema()

def _run_nslookup(args):
    try:
        result = subprocess.run(["nslookup", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, text=True)
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return ""

def _check_spf(domain):
    out = _run_nslookup(["-type=TXT", domain])
    spf = None
    permissive = False
    for line in out.splitlines():
        if "v=spf1" in line:
            spf = line.strip()
            if "+all" in spf:
                permissive = True
    return {"present": bool(spf), "record": spf, "permissive": permissive}

def _check_dmarc(domain):
    out = _run_nslookup(["-type=TXT", f"_dmarc.{domain}"])
    rec = None
    policy = None
    for line in out.splitlines():
        if "v=DMARC1" in line.upper():
            rec = line.strip()
            # parse p=
            up = rec.replace(" ", "")
            idx = up.lower().find("p=")
            if idx != -1:
                policy = up[idx+2:].split(";")[0]
    return {"present": bool(rec), "record": rec, "policy": policy}

def _check_dkim(domain):
    selectors = ["default", "selector1", "s1", "dkim", "mail"]
    found = []
    for sel in selectors:
        out = _run_nslookup(["-type=TXT", f"{sel}._domainkey.{domain}"])
        if out:
            found.append({"selector": sel, "record": out.strip()})
    return {"present": bool(found), "records": found}

def _check_dnssec(domain):
    out = _run_nslookup(["-type=DNSKEY", domain])
    enabled = "DNSKEY" in out or "flags" in out.lower()
    return {"enabled": enabled}

def _check_mx(domain):
    out = _run_nslookup(["-type=MX", domain])
    mx = []
    for line in out.splitlines():
        if "mail exchanger" in line:
            parts = line.split("=")
            host = parts[-1].strip().rstrip('.') if parts else line.strip()
            mx.append(host)
    return {"records": mx}

def _tls_check(domain):
    info = {"expiry": None, "trusted": None, "protocol": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            info["protocol"] = s.version()
            not_after = cert.get('notAfter')
            if not_after:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                info["expiry"] = exp.strftime("%Y-%m-%d")
            info["trusted"] = True
    except ssl.SSLError:
        info["trusted"] = False
    except Exception:
        pass
    # Protocol assessment
    weak_protocol = info.get("protocol") in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
    info["weak_protocol"] = weak_protocol
    return info

def _http_headers(domain):
    headers = {}
    try:
        import urllib.request
        req = urllib.request.Request(url=f"https://{domain}/", method="GET")
        with urllib.request.urlopen(req, timeout=6) as resp:
            hdrs = resp.headers
            for k in [
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "Referrer-Policy",
                "Permissions-Policy",
            ]:
                headers[k] = hdrs.get(k)
    except Exception:
        pass
    return headers

def _blacklist_status(domain):
    # Placeholder unless APIs configured. Returns unknown by default.
    return {"status": "unknown"}

def _subdomains(domain):
    subs = []
    try:
        import json
        import urllib.request
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        with urllib.request.urlopen(url, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
            for item in data:
                name = item.get("name_value")
                if name and domain in name:
                    for sub in name.split('\n'):
                        if sub not in subs:
                            subs.append(sub)
    except Exception:
        pass
    return {"count": len(subs), "items": subs[:50]}

def _ports(domain):
    open_ports = []
    ports = [21, 22, 25, 80, 443, 3306]
    for p in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((domain, p)) == 0:
                open_ports.append(p)
            sock.close()
        except Exception:
            pass
    return {"open": open_ports}

def scan_domain_security(domain):
    result = {
        "domain": domain,
        "scanned_at": datetime.datetime.now().isoformat(sep=' ', timespec='seconds'),
        "dns_email": {
            "spf": _check_spf(domain),
            "dkim": _check_dkim(domain),
            "dmarc": _check_dmarc(domain),
            "dnssec": _check_dnssec(domain),
            "mx": _check_mx(domain),
        },
        "tls": _tls_check(domain),
        "http_headers": _http_headers(domain),
        "reputation": _blacklist_status(domain),
        "subdomains": _subdomains(domain),
        "ports": _ports(domain),
    }
    # Summary badge
    critical = False
    warning = False
    # SPF
    spf = result["dns_email"]["spf"]
    if not spf["present"] or spf.get("permissive"):
        warning = True
    # DMARC
    dmarc = result["dns_email"]["dmarc"]
    if not dmarc["present"] or (dmarc.get("policy") in (None, "none")):
        warning = True
    # TLS
    tls = result["tls"]
    if tls.get("weak_protocol") or tls.get("trusted") is False:
        critical = True
    # Ports
    ports = result["ports"].get("open", [])
    risky_ports = {21, 22, 25, 3306}
    if any(p in risky_ports for p in ports):
        warning = True
    # Reputation
    if result["reputation"].get("status") == "blacklisted":
        critical = True

    if critical:
        summary = "critical"
    elif warning:
        summary = "at_risk"
    else:
        summary = "secure"
    result["summary_status"] = summary
    return result

@app.route('/api/domain-security/scan', methods=['POST', 'GET'])
@login_required
def api_domain_security_scan():
    user = get_current_user()
    domain = request.args.get('domain') or (request.json.get('domain') if request.is_json else request.form.get('domain'))
    if not domain:
        return jsonify({"error": "domain required"}), 400
    # RBAC: allowed by location
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name, location FROM domains WHERE name=?", (domain,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "domain not found"}), 404
    if user and user["role"] in ("admin", "analytics") and not user_can_access_location(user, row["location"]):
        conn.close()
        return jsonify({"error": "access denied"}), 403
    # Scan
    result = scan_domain_security(domain)
    import json as _json
    c.execute("INSERT INTO domain_security(domain_name, scanned_at, summary_status, details_json) VALUES(?, ?, ?, ?)",
              (domain, result["scanned_at"], result["summary_status"], _json.dumps(result)))
    conn.commit()
    conn.close()
    return jsonify(result)

@app.route('/api/domain-security/latest')
@login_required
def api_domain_security_latest():
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    base_sql = """
        SELECT d.name as domain, d.location,
               ds.summary_status, ds.scanned_at, ds.details_json
        FROM domains d
        LEFT JOIN (
            SELECT x.domain_name, x.summary_status, x.scanned_at, x.details_json
            FROM domain_security x
            JOIN (
                SELECT domain_name, MAX(scanned_at) as max_ts
                FROM domain_security
                GROUP BY domain_name
            ) y ON x.domain_name = y.domain_name AND x.scanned_at = y.max_ts
        ) ds ON ds.domain_name = d.name
    """
    params = []
    if user and user["role"] in ("admin", "analytics"):
        base_sql += " WHERE LOWER(d.location)=LOWER(?)"
        params.append(user["location"] or "")
    base_sql += " ORDER BY d.name"
    c.execute(base_sql, params)
    rows = c.fetchall()
    out = []
    for r in rows:
        out.append({
            "domain": r["domain"],
            "location": r["location"],
            "summary_status": r["summary_status"],
            "scanned_at": r["scanned_at"],
        })
    conn.close()
    return jsonify({"domains": out})

@app.route('/domain/security/<path:domain>')
@login_required
def domain_security_details(domain):
    """Render a full-page security details view for a domain using the latest scan.
    If no scan exists, trigger a scan first.
    """
    user = get_current_user()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT name, location FROM domains WHERE name=?", (domain,))
    row = c.fetchone()
    if not row:
        conn.close()
        flash("Domain not found.", "danger")
        return redirect(url_for('domain'))
    if user and user["role"] in ("admin", "analytics") and not user_can_access_location(user, row["location"]):
        conn.close()
        flash("Access denied for this location.", "danger")
        return redirect(url_for('domain'))

    # Get latest security scan; if absent, run one
    c.execute(
        """
        SELECT details_json, scanned_at, summary_status
        FROM domain_security
        WHERE domain_name=?
        ORDER BY scanned_at DESC
        LIMIT 1
        """,
        (domain,)
    )
    latest = c.fetchone()
    import json as _json
    if not latest:
        result = scan_domain_security(domain)
        c.execute(
            "INSERT INTO domain_security(domain_name, scanned_at, summary_status, details_json) VALUES(?, ?, ?, ?)",
            (domain, result["scanned_at"], result["summary_status"], _json.dumps(result))
        )
        conn.commit()
        details = result
    else:
        details = _json.loads(latest["details_json"]) if latest and latest["details_json"] else None
    conn.close()

    if not details:
        flash("Failed to load domain security details.", "danger")
        return redirect(url_for('domain'))

    return render_template('domain_security.html', details=details, user=user)

# periodic scanner
_domain_scanner_started = False

def _domain_security_scanner_loop(interval_hours=6):
    while True:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT name FROM domains")
            domains = [r[0] for r in c.fetchall()]
            conn.close()
            for d in domains:
                try:
                    # Best-effort scan, ignore failures
                    res = scan_domain_security(d)
                    conn2 = get_db_connection()
                    c2 = conn2.cursor()
                    import json as _json
                    c2.execute("INSERT INTO domain_security(domain_name, scanned_at, summary_status, details_json) VALUES(?, ?, ?, ?)",
                              (d, res["scanned_at"], res["summary_status"], _json.dumps(res)))
                    conn2.commit()
                    conn2.close()
                except Exception as _e:
                    pass
        except Exception as e:
            print("[domain_scanner] error:", e)
        time.sleep(max(60, int(interval_hours*3600)))

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
                    # Immediate and repeated alerts, race-safe: acquire 'send right' via UPDATE first
                    for a in alerts:
                        email = a[0]
                        last_sent = a[1]
                        # Determine threshold time
                        threshold = now - datetime.timedelta(minutes=repeat_minutes)
                        threshold_iso = threshold.isoformat(sep=' ', timespec='seconds')
                        # Try to atomically claim a send by updating last_alert_sent only if due
                        try:
                            c.execute(
                                """
                                UPDATE server_alerts
                                SET last_alert_sent=?
                                WHERE server_id=? AND email_address=?
                                  AND (
                                        last_alert_sent IS NULL OR last_alert_sent < ?
                                      )
                                """,
                                (now.isoformat(sep=' ', timespec='seconds'), sid, email, threshold_iso)
                            )
                            claimed = (c.rowcount == 1)
                            if claimed:
                                conn.commit()
                        except Exception:
                            claimed = False
                        if not claimed:
                            continue
                        # We have the send right; send email
                        subject = f"[ALERT] Server OFFLINE: {s['name']}"
                        body = _format_server_summary(s) + f"\nStatus: Offline\nTimestamp: {now.strftime('%Y-%m-%d %H:%M:%S')}\nServer has gone offline."
                        ok, err = _send_server_email(email, subject, body)
                        if not ok:
                            # On failure, roll back claim to allow future retries
                            try:
                                c.execute("UPDATE server_alerts SET last_alert_sent=NULL WHERE server_id=? AND email_address=? AND last_alert_sent=?", (sid, email, now.isoformat(sep=' ', timespec='seconds')))
                                conn.commit()
                            except Exception:
                                pass
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
    global _watcher_thread_started, _pinger_thread_started, _domain_scanner_started
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
    if not _domain_scanner_started:
        ds = threading.Thread(target=_domain_security_scanner_loop, kwargs={"interval_hours": 6}, daemon=True)
        ds.start()
        _domain_scanner_started = True

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

