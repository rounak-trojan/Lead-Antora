"""Lead Antora — multi-center admission CRM: Flask + built-in SQLite. No external database needed."""
import base64
import calendar
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta
from functools import wraps
from urllib.parse import quote, urlencode
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

# =====================================================================
#  SUPER ADMIN — static login, not stored in the database.
#  Change the password before going live. Minimum 10 characters.
#  Changing it here signs out any active super admin session.
# =====================================================================
SUPERADMIN_USERNAME = 'rounak'
SUPERADMIN_PASSWORD = 'Change-This-Now@2026'
# =====================================================================

BRAND = 'Lead Antora'

if len(SUPERADMIN_PASSWORD) < 10:
    raise RuntimeError('SUPERADMIN_PASSWORD in app.py must be at least 10 characters.')

BASE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE, '.env'), override=False)


def load_secret_key():
    key = (os.environ.get('SECRET_KEY') or '').strip()
    if key:
        return key
    path = os.path.join(BASE, '.secret_key')
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)

TZ = ZoneInfo(os.environ.get('APP_TZ', 'Asia/Kolkata'))
STAGES = ['New', 'Contacted', 'Interested', 'Demo scheduled', 'Demo attended',
          'Negotiation', 'Enrolled', 'Lost']
OPEN = STAGES[:6]
ACT_TYPES = ['Call', 'WhatsApp', 'Visit', 'Demo', 'Email', 'Note']
PER_PAGE = 50
RENEW_OPTIONS = (1, 3, 6, 12)
DEFAULTS = {
    'inst': BRAND,
    'courses': 'NEET 2027, JEE 2027, UPSC Foundation, Class 11 Foundation',
    'sources': 'Website, Instagram, Instagram Ads, Facebook, Facebook Ads, YouTube, YouTube Ads, '
               'Google Ads, Walk-in, Referral, Seminar, Phone call',
    'lost_reasons': 'Fee too high, Joined competitor, Not interested, Unreachable, Timing issue',
    'wa_template': 'Hi {name}, this is {counsellor} from {inst}. Following up on your '
                   'interest in {course}. When is a good time to talk?',
    'rr': '0',
}
LIST_KEYS = ('courses', 'sources', 'lost_reasons')
FAILS = {}

# Secrets saved by center admins (Meta app secret, page tokens, Google key) are encrypted with a
# key derived from SECRET_KEY. Changing SECRET_KEY makes them unreadable; admins must re-enter them.
_FERNET = Fernet(base64.urlsafe_b64encode(hashlib.sha256(f'webhooks|{app.secret_key}'.encode()).digest()))


def enc(s):
    return _FERNET.encrypt(s.encode()).decode() if s else ''


def dec(s):
    if not s:
        return ''
    try:
        return _FERNET.decrypt(s.encode()).decode()
    except InvalidToken:
        return ''


# ---------- helpers ----------
def now():
    return datetime.now(TZ).replace(tzinfo=None, microsecond=0)


def today():
    return now().date()


def add_months(d, m):
    y, mo = divmod(d.month - 1 + m, 12)
    y, mo = d.year + y, mo + 1
    return d.replace(year=y, month=mo, day=min(d.day, calendar.monthrange(y, mo)[1]))


def phone10(p):
    return re.sub(r'\D', '', p or '')[-10:]


def pdate(s):
    try:
        return datetime.strptime((s or '').strip(), '%Y-%m-%d').date()
    except ValueError:
        return None


def num(v):
    try:
        return min(max(0.0, round(float(v), 2)), 1e9)
    except (TypeError, ValueError):
        return 0.0


def ph(n):
    return ','.join(['%s'] * n)


def inr(v):
    n = int(round(float(v or 0)))
    s = str(abs(n))
    if len(s) > 3:
        head = re.sub(r'(\d)(?=(\d\d)+$)', r'\1,', s[:-3])
        s = head + ',' + s[-3:]
    return ('-' if n < 0 else '') + '₹' + s


def pct(a, b):
    a, b = int(a or 0), int(b or 0)
    return f'{round(a * 100 / b)}%' if b else '—'


def csv_safe(v):
    s = '' if v is None else str(v)
    return "'" + s if s[:1] in ('=', '+', '-', '@') else s


# ---------- built-in SQLite database (created automatically) ----------
DB_PATH = os.environ.get('DB_PATH') or os.path.join(BASE, 'data', 'leads.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

sqlite3.register_adapter(date, lambda d: d.isoformat())
sqlite3.register_adapter(datetime, lambda d: d.isoformat(sep=' '))
sqlite3.register_converter('DATE', lambda b: date.fromisoformat(b.decode()[:10]))
sqlite3.register_converter('DATETIME', lambda b: datetime.fromisoformat(b.decode()))

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS centers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        city TEXT,
        active INTEGER NOT NULL DEFAULT 1,
        active_until DATE NOT NULL,
        created_at DATETIME NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        center_id INTEGER NOT NULL REFERENCES centers(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'counsellor' CHECK (role IN ('admin', 'counsellor')),
        is_primary INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS leads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        center_id INTEGER NOT NULL REFERENCES centers(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        phone10 TEXT NOT NULL,
        parent_phone TEXT,
        email TEXT,
        city TEXT,
        target TEXT,
        course TEXT,
        source TEXT,
        stage TEXT NOT NULL DEFAULT 'New',
        assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
        next_followup DATE,
        notes TEXT,
        fee REAL NOT NULL DEFAULT 0,
        paid REAL NOT NULL DEFAULT 0,
        lost_reason TEXT,
        created_at DATETIME NOT NULL,
        UNIQUE (center_id, phone10))""",
    """CREATE TABLE IF NOT EXISTS activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        type TEXT NOT NULL,
        text TEXT NOT NULL,
        created_at DATETIME NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS settings (
        center_id INTEGER NOT NULL REFERENCES centers(id) ON DELETE CASCADE,
        k TEXT NOT NULL,
        v TEXT NOT NULL,
        PRIMARY KEY (center_id, k))""",
    """CREATE TABLE IF NOT EXISTS integrations (
        center_id INTEGER PRIMARY KEY REFERENCES centers(id) ON DELETE CASCADE,
        token TEXT NOT NULL UNIQUE,
        ch_instagram INTEGER NOT NULL DEFAULT 1,
        ch_facebook INTEGER NOT NULL DEFAULT 1,
        ch_google INTEGER NOT NULL DEFAULT 1,
        ch_youtube INTEGER NOT NULL DEFAULT 1,
        ch_website INTEGER NOT NULL DEFAULT 1,
        meta_app_id TEXT,
        meta_app_secret TEXT,
        meta_verify TEXT NOT NULL,
        google_key TEXT,
        youtube_forms TEXT,
        updated_at DATETIME)""",
    """CREATE TABLE IF NOT EXISTS meta_pages (
        center_id INTEGER NOT NULL REFERENCES centers(id) ON DELETE CASCADE,
        page_id TEXT NOT NULL,
        name TEXT,
        token TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (center_id, page_id))""",
    """CREATE TABLE IF NOT EXISTS inbound (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        center_id INTEGER REFERENCES centers(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        channel TEXT NOT NULL,
        ext_id TEXT NOT NULL,
        status TEXT NOT NULL,
        detail TEXT,
        lead_id INTEGER REFERENCES leads(id) ON DELETE SET NULL,
        payload TEXT NOT NULL,
        created_at DATETIME NOT NULL,
        UNIQUE (center_id, provider, ext_id))""",
    """CREATE TABLE IF NOT EXISTS demo_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        institute TEXT NOT NULL,
        city TEXT,
        centers TEXT,
        message TEXT,
        status TEXT NOT NULL DEFAULT 'new',
        created_at DATETIME NOT NULL)""",
    'CREATE INDEX IF NOT EXISTS ix_users_center ON users(center_id)',
    'CREATE INDEX IF NOT EXISTS ix_leads_assigned ON leads(assigned_to)',
    'CREATE INDEX IF NOT EXISTS ix_leads_center_stage ON leads(center_id, stage)',
    'CREATE INDEX IF NOT EXISTS ix_leads_next ON leads(next_followup)',
    'CREATE INDEX IF NOT EXISTS ix_leads_created ON leads(created_at)',
    'CREATE INDEX IF NOT EXISTS ix_act_lead ON activities(lead_id)',
    'CREATE INDEX IF NOT EXISTS ix_act_user_time ON activities(user_id, created_at)',
    'CREATE INDEX IF NOT EXISTS ix_inbound_center ON inbound(center_id, channel, id)',
    'CREATE INDEX IF NOT EXISTS ix_inbound_time ON inbound(created_at)',
]


def connect():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES,
                           timeout=15, isolation_level=None)
    conn.row_factory = lambda cur, row: {d[0]: row[i] for i, d in enumerate(cur.description)}
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 15000')
    return conn


_db_ready = False


def init_db():
    global _db_ready
    if _db_ready:
        return
    conn = connect()
    try:
        conn.execute('PRAGMA journal_mode = WAL')
        for stmt in SCHEMA:
            conn.execute(stmt)
    finally:
        conn.close()
    _db_ready = True
    app.logger.info('Database ready at %s', DB_PATH)


def db():
    if 'db' not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_e):
    conn = g.pop('db', None)
    if conn:
        conn.close()


def _sql(s):
    return s.replace('%s', '?')


def q(sql, args=(), one=False):
    rows = db().execute(_sql(sql), tuple(args)).fetchall()
    return (rows[0] if rows else None) if one else rows


def x(sql, args=()):
    return db().execute(_sql(sql), tuple(args)).lastrowid


@app.errorhandler(sqlite3.OperationalError)
def db_error(e):
    app.logger.error('Database error: %s', e)
    text = str(e).lower()
    if 'locked' in text or 'busy' in text:
        msg = 'The database is busy saving other changes. Wait a few seconds and reload.'
    elif 'unable to open' in text or 'readonly' in text:
        msg = (f'The app cannot write to {os.path.dirname(DB_PATH)}. '
               'Give the app write permission on that folder.')
    else:
        msg = 'Unexpected database error. Check the server log for details.'
    html = ('<!doctype html><meta charset="utf-8"><title>Database error</title>'
            '<div style="font-family:system-ui;max-width:560px;margin:60px auto;padding:20px;'
            'border:1px solid #e4e7ef;border-radius:12px">'
            f'<h1 style="font-size:20px">Database error</h1><p>{msg}</p></div>')
    return Response(html, status=503, mimetype='text/html')


# ---------- current center and per-center settings ----------
def cid():
    u = g.get('user')
    return u['center_id'] if u else None


def cfg():
    if 'cfg' not in g:
        c = dict(DEFAULTS)
        if cid():
            c.update({r['k']: r['v'] for r in q('SELECT k, v FROM settings WHERE center_id=%s', (cid(),))})
        for k in LIST_KEYS:
            c[k] = [s.strip() for s in c[k].split(',') if s.strip()]
        g.cfg = c
    return g.cfg


def set_cfg(k, v, center=None):
    x('INSERT INTO settings (center_id, k, v) VALUES (%s, %s, %s) '
      'ON CONFLICT(center_id, k) DO UPDATE SET v = excluded.v', (center or cid(), k, v))
    g.pop('cfg', None)


# ---------- domain helpers (all center-scoped) ----------
def uname(uid):
    if not uid:
        return 'Unassigned'
    r = q('SELECT name FROM users WHERE id=%s', (uid,), one=True)
    return r['name'] if r else 'Unassigned'


def active_counsellors(skip=None):
    return [r['id'] for r in q(
        "SELECT id FROM users WHERE center_id=%s AND role='counsellor' AND active=1 AND id<>%s ORDER BY id",
        (cid(), skip or 0))]


def round_robin(ids):
    rr = int(cfg()['rr'])
    try:
        while True:
            yield ids[rr % len(ids)] if ids else None
            rr += 1
    finally:
        set_cfg('rr', str(rr))


def next_counsellor(skip=None):
    gen = round_robin(active_counsellors(skip))
    c = next(gen)
    gen.close()
    return c


def valid_counsellor(val):
    if val and str(val).isdigit() and q(
            "SELECT 1 FROM users WHERE id=%s AND center_id=%s AND role='counsellor'",
            (int(val), cid()), one=True):
        return int(val)
    return None


def counsellor_names():
    return {r['id']: r['name'] for r in q(
        "SELECT id, name FROM users WHERE center_id=%s AND role='counsellor'", (cid(),))}


def log(lid, typ, text):
    x('INSERT INTO activities (lead_id, user_id, type, text, created_at) VALUES (%s,%s,%s,%s,%s)',
      (lid, g.user['id'], typ, text, now()))


def scope():
    if g.user['role'] == 'admin':
        return 'l.center_id=%s', (cid(),)
    return 'l.center_id=%s AND l.assigned_to=%s', (cid(), g.user['id'])


def get_lead(lid):
    l = q('SELECT l.*, u.name AS counsellor FROM leads l '
          'LEFT JOIN users u ON u.id=l.assigned_to WHERE l.id=%s AND l.center_id=%s',
          (lid, cid()), one=True)
    if not l or (g.user['role'] != 'admin' and l['assigned_to'] != g.user['id']):
        abort(404)
    return l


def insert_lead(d, aid, nf):
    return x('INSERT INTO leads (center_id, name, phone, phone10, parent_phone, email, city, target, '
             'course, source, stage, assigned_to, next_followup, notes, created_at) '
             'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
             (cid(), d['name'], d['phone'], phone10(d['phone']), d.get('parent_phone') or None,
              d.get('email') or None, d.get('city') or None, d.get('target') or None,
              d.get('course') or None, d.get('source') or None, 'New', aid, nf,
              d.get('notes') or None, now()))


def back(default):
    ref = request.referrer or ''
    return ref if ref.startswith(request.host_url) else default


def center_open(row):
    return bool(row['center_active']) and row['active_until'] >= today()


def center_block_msg(row):
    if not row['center_active']:
        return f"{row['center_name']} access is suspended. Contact the super admin."
    return f"{row['center_name']} access expired on {row['active_until'].strftime('%d %b %Y')}. " \
           'Contact the super admin to renew.'


USER_SQL = ('SELECT u.*, c.name AS center_name, c.active AS center_active, c.active_until '
            'FROM users u JOIN centers c ON c.id=u.center_id ')


# ---------- security, auth, template globals ----------
def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']


def sa_token():
    raw = f'{app.secret_key}|{SUPERADMIN_USERNAME}|{SUPERADMIN_PASSWORD}'
    return hashlib.sha256(raw.encode()).hexdigest()


def wa_link(l):
    vals = {'name': l['name'], 'course': l.get('course') or '', 'inst': cfg()['inst'],
            'counsellor': l.get('counsellor') or (g.user['name'] if g.get('user') else '')}
    text = re.sub(r'\{(\w+)\}', lambda m: vals.get(m.group(1), ''), cfg()['wa_template'])
    return f"https://wa.me/91{phone10(l['phone'])}?text={quote(text)}"


app.jinja_env.globals.update(
    csrf_field=lambda: Markup(f'<input type="hidden" name="_csrf" value="{csrf_token()}">'),
    wa_link=wa_link, pct=pct, brand=BRAND)
app.jinja_env.filters['inr'] = inr


@app.context_processor
def ctx():
    u = g.get('user')
    days_left = (u['active_until'] - today()).days if u and u.get('active_until') else None
    return {'user': u, 'cfg': cfg(), 'today': today(), 'STAGES': STAGES, 'OPEN': OPEN,
            'days_left': days_left}


@app.before_request
def load_user():
    init_db()
    g.user = None
    if request.path.startswith('/hook/'):
        return  # external webhooks: no session, no CSRF; each endpoint authenticates itself
    if request.method == 'POST' and request.form.get('_csrf') != session.get('_csrf'):
        abort(400, 'Your session expired. Go back, refresh the page, and try again.')
    if session.get('sa'):
        if secrets.compare_digest(session['sa'], sa_token()):
            g.user = {'id': 0, 'name': 'Super Admin', 'username': SUPERADMIN_USERNAME,
                      'role': 'superadmin', 'center_id': None}
        else:
            session.clear()
        return
    uid = session.get('uid')
    if uid:
        u = q(USER_SQL + 'WHERE u.id=%s', (uid,), one=True)
        if not u or not u['active'] or session.get('pwv') != u['password_hash'][-12:]:
            session.clear()
            return
        if not center_open(u):
            session.clear()
            flash(center_block_msg(u), 'error')
            return
        g.user = u


@app.after_request
def headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'same-origin'
    return resp


def login_required(f):
    """Center users only (admin or counsellor)."""
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for('login', next=request.path))
        if g.user['role'] == 'superadmin':
            return redirect(url_for('centers'))
        return f(*a, **k)
    return w


def admin_required(f):
    """Center admins only."""
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for('login', next=request.path))
        if g.user['role'] == 'superadmin':
            return redirect(url_for('centers'))
        if g.user['role'] != 'admin':
            abort(403)
        return f(*a, **k)
    return w


def superadmin_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            return redirect(url_for('login', next=request.path, role='super'))
        if g.user['role'] != 'superadmin':
            abort(403)
        return f(*a, **k)
    return w


def validate_user(name, un, pw):
    if not name:
        return 'Enter the full name.'
    if not re.fullmatch(r'[a-z0-9._]{3,50}', un):
        return 'Username needs 3 to 50 characters: lowercase letters, numbers, dot, underscore.'
    if un == SUPERADMIN_USERNAME.lower():
        return 'That username is reserved.'
    if len(pw) < 8:
        return 'Password needs at least 8 characters.'
    if q('SELECT 1 FROM users WHERE username=%s', (un,), one=True):
        return 'That username is taken.'
    return None


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
def http_error(e):
    titles = {400: 'Request rejected', 403: 'Not allowed', 404: 'Not found'}
    return render_template('message.html', title=titles[e.code], msg=e.description), e.code


# ---------- public landing page and demo requests ----------
@app.route('/')
def landing():
    if g.user:
        return redirect(url_for('centers' if g.user['role'] == 'superadmin' else 'dashboard'))
    return render_template('landing.html')


@app.route('/demo', methods=['POST'])
def demo_request():
    f = request.form
    back_to = url_for('landing') + '#demo'
    if f.get('website'):  # honeypot: only bots fill it
        return redirect(back_to)
    name = f.get('name', '').strip()[:100]
    phone = f.get('phone', '').strip()[:20]
    inst = f.get('institute', '').strip()[:120]
    if not name or not inst or len(phone10(phone)) < 10:
        flash('Enter your name, institute and a valid 10-digit mobile number.', 'error')
        return redirect(back_to)
    if not hook_rate_ok(limit=5, window=3600):
        flash('Too many requests from this network. Try again later.', 'error')
        return redirect(back_to)
    x('INSERT INTO demo_requests (name, phone, institute, city, centers, message, created_at) '
      'VALUES (%s,%s,%s,%s,%s,%s,%s)',
      (name, phone, inst, f.get('city', '').strip()[:80] or None, f.get('centers', '').strip()[:20] or None,
       f.get('message', '').strip()[:1000] or None, now()))
    flash('Thank you. Our team will call you within one working day to schedule your demo.', 'ok')
    return redirect(back_to)


# ---------- login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('centers' if g.user['role'] == 'superadmin' else 'dashboard'))
    if request.method == 'POST':
        ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()
        recent = [t for t in FAILS.get(ip, []) if time.time() - t < 900]
        FAILS[ip] = recent
        if len(recent) >= 5:
            flash('Too many failed attempts. Try again in 15 minutes.', 'error')
            return render_template('login.html'), 429
        un = request.form.get('username', '').strip().lower()
        pw = request.form.get('password', '')

        if un == SUPERADMIN_USERNAME.lower():
            if secrets.compare_digest(pw.encode(), SUPERADMIN_PASSWORD.encode()):
                session.clear()
                session.permanent = True
                session['sa'] = sa_token()
                return redirect(url_for('centers'))
            recent.append(time.time())
            flash('Wrong username or password.', 'error')
            return render_template('login.html')

        u = q(USER_SQL + 'WHERE u.username=%s', (un,), one=True)
        if not u or not check_password_hash(u['password_hash'], pw):
            recent.append(time.time())
            flash('Wrong username or password.', 'error')
        elif not u['active']:
            flash('This account is deactivated. Contact your admin.', 'error')
        elif not center_open(u):
            flash(center_block_msg(u), 'error')
        else:
            session.clear()
            session.permanent = True
            session['uid'], session['pwv'] = u['id'], u['password_hash'][-12:]
            nxt = request.args.get('next', '')
            return redirect(nxt if nxt.startswith('/') and not nxt.startswith('//') else url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('landing'))


# ---------- super admin: centers ----------
@app.route('/centers')
@superadmin_required
def centers():
    rows = q("""SELECT c.*,
        (SELECT COUNT(*) FROM users u WHERE u.center_id=c.id) AS users,
        (SELECT COUNT(*) FROM leads l WHERE l.center_id=c.id) AS leads,
        (SELECT COUNT(*) FROM leads l WHERE l.center_id=c.id AND l.stage='Enrolled') AS enrolled
        FROM centers c ORDER BY c.name""")
    t = today()
    for c in rows:
        c['days_left'] = (c['active_until'] - t).days
        c['status'] = 'Suspended' if not c['active'] else ('Expired' if c['days_left'] < 0 else 'Active')
    admins = {}
    for a in q('SELECT id, center_id, name, username, active FROM users WHERE is_primary=1 ORDER BY name'):
        admins.setdefault(a['center_id'], []).append(a)
    demos = q("SELECT * FROM demo_requests ORDER BY (status='new') DESC, id DESC LIMIT 100")
    new_demos = sum(1 for d in demos if d['status'] == 'new')
    return render_template('centers.html', centers=rows, admins=admins, renew=RENEW_OPTIONS,
                           demos=demos, new_demos=new_demos)


@app.route('/centers/demo/<int:did>', methods=['POST'])
@superadmin_required
def demo_update(did):
    act = request.form.get('action')
    if act == 'contacted':
        x("UPDATE demo_requests SET status='contacted' WHERE id=%s", (did,))
        flash('Demo request marked as contacted.', 'ok')
    elif act == 'delete':
        x('DELETE FROM demo_requests WHERE id=%s', (did,))
        flash('Demo request deleted.', 'ok')
    return redirect(url_for('centers') + '#demos')


@app.route('/centers/backup')
@superadmin_required
def backup_db():
    fd, tmp = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    try:
        dst = sqlite3.connect(tmp)
        db().backup(dst)
        dst.close()
        with open(tmp, 'rb') as f:
            data = f.read()
    finally:
        os.remove(tmp)
    return Response(data, mimetype='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename=lead-antora-backup-{today()}.db'})


def get_center(center_id):
    c = q('SELECT * FROM centers WHERE id=%s', (center_id,), one=True)
    if not c:
        abort(404)
    return c


def create_primary_admin(center_id, f):
    name = f.get('admin_name', '').strip()[:100]
    un = f.get('admin_username', '').strip().lower()
    pw = f.get('admin_password', '')
    err = validate_user(name, un, pw)
    if err:
        return err
    x('INSERT INTO users (center_id, name, username, password_hash, role, is_primary, active, created_at) '
      'VALUES (%s,%s,%s,%s,%s,1,1,%s)', (center_id, name, un, generate_password_hash(pw), 'admin', now()))
    return None


@app.route('/centers/create', methods=['POST'])
@superadmin_required
def center_create():
    f = request.form
    name, city = f.get('name', '').strip()[:120], f.get('city', '').strip()[:80]
    months = int(f.get('months', 1)) if f.get('months', '').isdigit() else 1
    if not name:
        flash('Enter the center name.', 'error')
        return redirect(url_for('centers'))
    if q('SELECT 1 FROM centers WHERE name=%s', (name,), one=True):
        flash('A center with that name already exists.', 'error')
        return redirect(url_for('centers'))
    admin_err = validate_user(f.get('admin_name', '').strip(), f.get('admin_username', '').strip().lower(),
                              f.get('admin_password', ''))
    if admin_err:
        flash(admin_err, 'error')
        return redirect(url_for('centers'))
    center_id = x('INSERT INTO centers (name, city, active, active_until, created_at) VALUES (%s,%s,1,%s,%s)',
                  (name, city or None, add_months(today(), max(1, min(months, 24))), now()))
    set_cfg('inst', name, center=center_id)
    create_primary_admin(center_id, f)
    flash(f'{name} created and active for {months} month(s). Share the main admin login privately.', 'ok')
    return redirect(url_for('centers'))


@app.route('/centers/<int:center_id>/renew', methods=['POST'])
@superadmin_required
def center_renew(center_id):
    c = get_center(center_id)
    months = int(request.form.get('months', 1)) if request.form.get('months', '').isdigit() else 1
    if months not in RENEW_OPTIONS:
        abort(400)
    until = add_months(max(today(), c['active_until']), months)
    x('UPDATE centers SET active_until=%s, active=1 WHERE id=%s', (until, center_id))
    flash(f"{c['name']} renewed until {until.strftime('%d %b %Y')}.", 'ok')
    return redirect(url_for('centers'))


@app.route('/centers/<int:center_id>/set-date', methods=['POST'])
@superadmin_required
def center_set_date(center_id):
    c = get_center(center_id)
    until = pdate(request.form.get('until'))
    if not until:
        flash('Pick a valid date.', 'error')
    else:
        x('UPDATE centers SET active_until=%s WHERE id=%s', (until, center_id))
        flash(f"{c['name']} access set until {until.strftime('%d %b %Y')}.", 'ok')
    return redirect(url_for('centers'))


@app.route('/centers/<int:center_id>/toggle', methods=['POST'])
@superadmin_required
def center_toggle(center_id):
    c = get_center(center_id)
    x('UPDATE centers SET active=%s WHERE id=%s', (0 if c['active'] else 1, center_id))
    flash(f"{c['name']} {'suspended' if c['active'] else 'resumed'}.", 'ok')
    return redirect(url_for('centers'))


@app.route('/centers/<int:center_id>/admins/create', methods=['POST'])
@superadmin_required
def center_admin_create(center_id):
    c = get_center(center_id)
    err = create_primary_admin(center_id, request.form)
    flash(err or f"Main admin added to {c['name']}.", 'error' if err else 'ok')
    return redirect(url_for('centers'))


def get_primary(uid):
    u = q('SELECT * FROM users WHERE id=%s AND is_primary=1', (uid,), one=True)
    if not u:
        abort(404)
    return u


@app.route('/centers/admins/<int:uid>/toggle', methods=['POST'])
@superadmin_required
def center_admin_toggle(uid):
    u = get_primary(uid)
    x('UPDATE users SET active=%s WHERE id=%s', (0 if u['active'] else 1, uid))
    flash(f"{u['name']} {'deactivated' if u['active'] else 'activated'}.", 'ok')
    return redirect(url_for('centers'))


@app.route('/centers/admins/<int:uid>/reset', methods=['POST'])
@superadmin_required
def center_admin_reset(uid):
    u = get_primary(uid)
    tmp = secrets.token_urlsafe(8)[:10]
    x('UPDATE users SET password_hash=%s WHERE id=%s', (generate_password_hash(tmp), uid))
    flash(f"Temporary password for {u['name']} (@{u['username']}): {tmp} — share it privately.", 'ok')
    return redirect(url_for('centers'))


# ---------- center dashboard ----------
@app.route('/dashboard')
@login_required
def dashboard():
    rng, t = request.args.get('range', 'month'), today()
    start = t.replace(day=1) if rng == 'month' else t - timedelta(days=30) if rng == '30' else None
    if start is None:
        rng = 'all'
    sc, sa = scope()
    cr = 'AND l.created_at >= %s' if start else ''
    p = (start,) if start else ()
    W, A = f'WHERE {sc} {cr}', sa + p

    s = q(f"""SELECT COUNT(*) AS n, COALESCE(SUM(stage<>'New'),0) AS contacted,
              COALESCE(SUM(stage='Enrolled'),0) AS enrolled,
              COALESCE(SUM(CASE WHEN stage='Enrolled' THEN paid END),0) AS collected,
              COALESCE(SUM(CASE WHEN stage='Enrolled' THEN MAX(fee-paid,0) END),0) AS pending
              FROM leads l {W}""", A, one=True)
    f = q(f"""SELECT COALESCE(SUM(next_followup < %s),0) AS overdue, COALESCE(SUM(next_followup = %s),0) AS due
              FROM leads l WHERE {sc} AND stage IN ({ph(len(OPEN))})""",
          (t, t) + sa + tuple(OPEN), one=True)
    n = int(s['n'])
    metrics = [('Leads', n), ('Contacted', pct(s['contacted'], n)), ('Enrolled', int(s['enrolled'])),
               ('Conversion', pct(s['enrolled'], n)), ('Due today', int(f['due'])),
               ('Overdue', int(f['overdue'])), ('Fees collected', inr(s['collected'])),
               ('Fees pending', inr(s['pending']))]

    fc = {r['stage']: r['n'] for r in q(f'SELECT stage, COUNT(*) AS n FROM leads l {W} GROUP BY stage', A)}
    mx = max(fc.values(), default=0) or 1
    funnel = [(st, fc.get(st, 0), round(fc.get(st, 0) * 100 / mx)) for st in STAGES]

    def grp(col):
        return q(f"""SELECT COALESCE(NULLIF({col},''),'Not set') AS k, COUNT(*) AS n,
                     COALESCE(SUM(stage='Enrolled'),0) AS e FROM leads l {W}
                     GROUP BY k ORDER BY n DESC""", A)

    lost = q(f"""SELECT COALESCE(NULLIF(lost_reason,''),'Not recorded') AS k, COUNT(*) AS n
                 FROM leads l {W} AND stage='Lost' GROUP BY k ORDER BY n DESC""", A)

    team = []
    if g.user['role'] == 'admin':
        ca = 'AND a.created_at >= %s' if start else ''
        team = q(f"""SELECT u.id, u.name, u.active,
            (SELECT COUNT(*) FROM leads l WHERE l.assigned_to=u.id {cr}) AS leads,
            (SELECT COUNT(*) FROM leads l WHERE l.assigned_to=u.id AND l.stage='Enrolled' {cr}) AS enrolled,
            (SELECT COALESCE(SUM(l.paid),0) FROM leads l WHERE l.assigned_to=u.id AND l.stage='Enrolled' {cr}) AS collected,
            (SELECT COUNT(*) FROM activities a WHERE a.user_id=u.id AND a.type<>'System' {ca}) AS acts,
            (SELECT COUNT(*) FROM leads l WHERE l.assigned_to=u.id AND l.stage IN ({ph(len(OPEN))})
                AND l.next_followup < %s) AS overdue
            FROM users u WHERE u.center_id=%s AND u.role='counsellor' ORDER BY u.active DESC, u.name""",
                 p * 4 + tuple(OPEN) + (t, cid()))

    return render_template('dashboard.html', rng=rng, metrics=metrics, funnel=funnel,
                           sources=grp('l.source'), courses=grp('l.course'), lost=lost, team=team)


# ---------- leads ----------
def lead_form_data():
    f = request.form
    limits = {'name': 120, 'phone': 20, 'parent_phone': 20, 'email': 120, 'city': 80,
              'target': 120, 'course': 120, 'source': 80, 'notes': 2000}
    d = {k: (f.get(k) or '').strip()[:lim] for k, lim in limits.items()}
    errs = []
    if not d['name']:
        errs.append('Enter the student name.')
    if len(phone10(d['phone'])) < 10:
        errs.append('Enter a valid 10-digit phone number.')
    if d['parent_phone'] and len(phone10(d['parent_phone'])) < 10:
        errs.append('Parent phone needs 10 digits.')
    if d['email'] and not re.fullmatch(r'\S+@\S+\.\S+', d['email']):
        errs.append('Enter a valid email.')
    return d, errs


def duplicate_error(p10, exclude_id=0):
    dup = q('SELECT l.name, u.name AS c FROM leads l LEFT JOIN users u ON u.id=l.assigned_to '
            'WHERE l.center_id=%s AND l.phone10=%s AND l.id<>%s', (cid(), p10, exclude_id), one=True)
    return f"This number already exists: {dup['name']}, assigned to {dup['c'] or 'nobody'}." if dup else None


def counsellor_list():
    return q("SELECT id, name, active FROM users WHERE center_id=%s AND role='counsellor' ORDER BY name",
             (cid(),))


@app.route('/leads')
@login_required
def leads():
    sc, sa = scope()
    w, a = [sc], list(sa)
    s = request.args.get('q', '').strip()
    stage, course, aid = (request.args.get(k, '') for k in ('stage', 'course', 'aid'))
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    if s:
        w.append('(l.name LIKE %s OR l.phone LIKE %s OR l.parent_phone LIKE %s OR l.city LIKE %s OR l.email LIKE %s)')
        a += [f'%{s}%'] * 5
    if stage in STAGES:
        w.append('l.stage=%s')
        a.append(stage)
    if course:
        w.append('l.course=%s')
        a.append(course)
    is_admin = g.user['role'] == 'admin'
    if is_admin and aid == 'none':
        w.append('l.assigned_to IS NULL')
    elif is_admin and aid.isdigit():
        w.append('l.assigned_to=%s')
        a.append(int(aid))
    where = ' AND '.join(w)
    total = q(f'SELECT COUNT(*) AS n FROM leads l WHERE {where}', a, one=True)['n']
    rows = q(f"""SELECT l.*, u.name AS counsellor FROM leads l LEFT JOIN users u ON u.id=l.assigned_to
                 WHERE {where}
                 ORDER BY (l.stage IN ('Enrolled','Lost')), l.next_followup IS NULL, l.next_followup,
                          l.created_at DESC LIMIT %s OFFSET %s""", a + [PER_PAGE, (page - 1) * PER_PAGE])
    unassigned = 0
    if is_admin:
        unassigned = q(f"""SELECT COUNT(*) AS n FROM leads WHERE center_id=%s AND assigned_to IS NULL
                           AND stage IN ({ph(len(OPEN))})""", (cid(),) + tuple(OPEN), one=True)['n']
    qs = request.args.to_dict()
    qs.pop('page', None)
    return render_template('leads.html', rows=rows, total=total, page=page,
                           pages=max(1, -(-total // PER_PAGE)), qs=qs, args=request.args,
                           counsellors=counsellor_list() if is_admin else [], unassigned=unassigned)


@app.route('/leads/new', methods=['GET', 'POST'])
@login_required
def lead_new():
    is_admin = g.user['role'] == 'admin'
    if request.method == 'POST':
        d, errs = lead_form_data()
        dup = duplicate_error(phone10(d['phone']))
        if dup:
            errs.append(dup)
        if not errs:
            if is_admin:
                a = request.form.get('assigned_to', 'auto')
                aid = next_counsellor() if a == 'auto' else valid_counsellor(a)
            else:
                aid = g.user['id']
            nf = pdate(request.form.get('next_followup')) or today()
            try:
                lid = insert_lead(d, aid, nf)
            except sqlite3.IntegrityError:
                flash('This phone number was just added by someone else.', 'error')
                return redirect(url_for('leads'))
            log(lid, 'System', 'Lead created' + (f', assigned to {uname(aid)}' if aid else ''))
            flash('Lead saved' + (f', assigned to {uname(aid)}.' if aid else '.'), 'ok')
            return redirect(url_for('lead_detail', lid=lid))
        for e in errs:
            flash(e, 'error')
        return render_template('lead_form.html', lead=request.form.to_dict(), new=True,
                               counsellors=counsellor_list() if is_admin else [])
    return render_template('lead_form.html', new=True,
                           lead={'next_followup': today(), 'assigned_to': 'auto'},
                           counsellors=counsellor_list() if is_admin else [])


@app.route('/leads/<int:lid>/edit', methods=['GET', 'POST'])
@login_required
def lead_edit(lid):
    l = get_lead(lid)
    is_admin = g.user['role'] == 'admin'
    if request.method == 'POST':
        d, errs = lead_form_data()
        dup = duplicate_error(phone10(d['phone']), lid)
        if dup:
            errs.append(dup)
        if not errs:
            x('UPDATE leads SET name=%s, phone=%s, phone10=%s, parent_phone=%s, email=%s, city=%s, '
              'target=%s, course=%s, source=%s, notes=%s WHERE id=%s AND center_id=%s',
              (d['name'], d['phone'], phone10(d['phone']), d['parent_phone'] or None, d['email'] or None,
               d['city'] or None, d['target'] or None, d['course'] or None, d['source'] or None,
               d['notes'] or None, lid, cid()))
            log(lid, 'System', 'Lead details edited')
            if is_admin:
                na = valid_counsellor(request.form.get('assigned_to'))
                if na != l['assigned_to']:
                    x('UPDATE leads SET assigned_to=%s WHERE id=%s', (na, lid))
                    log(lid, 'System', f"Reassigned from {l['counsellor'] or 'Unassigned'} to {uname(na)}")
            flash('Lead updated.', 'ok')
            return redirect(url_for('lead_detail', lid=lid))
        for e in errs:
            flash(e, 'error')
        return render_template('lead_form.html', lead={**request.form.to_dict(), 'id': lid}, new=False,
                               counsellors=counsellor_list() if is_admin else [])
    return render_template('lead_form.html', lead=l, new=False,
                           counsellors=counsellor_list() if is_admin else [])


@app.route('/leads/<int:lid>')
@login_required
def lead_detail(lid):
    l = get_lead(lid)
    acts = q('SELECT a.*, u.name AS uname FROM activities a LEFT JOIN users u ON u.id=a.user_id '
             'WHERE a.lead_id=%s ORDER BY a.id DESC', (lid,))
    nf = l['next_followup']
    next_default = nf if nf and nf >= today() else today() + timedelta(days=2)
    return render_template('lead_detail.html', l=l, acts=acts, act_types=ACT_TYPES, next_default=next_default)


@app.route('/leads/<int:lid>/activity', methods=['POST'])
@login_required
def lead_activity(lid):
    l, f = get_lead(lid), request.form
    typ = f.get('type') if f.get('type') in ACT_TYPES else 'Note'
    text = f.get('text', '').strip()[:2000]
    stage = f.get('stage') if f.get('stage') in STAGES else l['stage']
    nx, fee, paid_now = pdate(f.get('next_followup')), num(f.get('fee')), num(f.get('paid_now'))
    reason = f.get('lost_reason', '').strip()[:120]
    err = None
    if not text:
        err = 'Describe what happened.'
    elif stage == 'Enrolled' and fee <= 0:
        err = 'Enter the total fee to mark as enrolled.'
    elif stage == 'Lost' and not reason:
        err = 'Pick a lost reason.'
    elif stage in OPEN and not nx:
        err = 'Set the next follow-up date. Open leads always need one.'
    elif stage in OPEN and nx < today():
        err = 'Next follow-up cannot be in the past.'
    if err:
        flash(err, 'error')
        return redirect(url_for('lead_detail', lid=lid))
    if stage == 'New' and typ != 'Note':
        stage = 'Contacted'
    msg = text + (f" · stage {l['stage']} → {stage}" if stage != l['stage'] else '')
    new_fee, new_paid, new_reason = l['fee'], float(l['paid']), l['lost_reason']
    if stage == 'Enrolled':
        new_fee = fee
        if paid_now > 0:
            new_paid += paid_now
            msg += f' · paid {inr(paid_now)}'
    if stage == 'Lost':
        new_reason = reason
        msg += f' · reason: {reason}'
    x('UPDATE leads SET stage=%s, next_followup=%s, fee=%s, paid=%s, lost_reason=%s WHERE id=%s',
      (stage, nx if stage in OPEN else None, new_fee, new_paid, new_reason, lid))
    log(lid, typ, msg)
    flash('Activity saved.', 'ok')
    return redirect(url_for('lead_detail', lid=lid))


@app.route('/leads/<int:lid>/payment', methods=['POST'])
@login_required
def lead_payment(lid):
    l, amt = get_lead(lid), num(request.form.get('amount'))
    if l['stage'] != 'Enrolled' or amt <= 0:
        flash('Enter a payment amount for an enrolled student.', 'error')
    else:
        total = float(l['paid']) + amt
        x('UPDATE leads SET paid=%s WHERE id=%s', (total, lid))
        log(lid, 'Payment', f'Received {inr(amt)} · total paid {inr(total)}')
        flash('Payment recorded.', 'ok')
    return redirect(url_for('lead_detail', lid=lid))


@app.route('/leads/<int:lid>/assign', methods=['POST'])
@admin_required
def lead_assign(lid):
    l = get_lead(lid)
    na = valid_counsellor(request.form.get('assigned_to'))
    if na != l['assigned_to']:
        x('UPDATE leads SET assigned_to=%s WHERE id=%s', (na, lid))
        log(lid, 'System', f"Reassigned from {l['counsellor'] or 'Unassigned'} to {uname(na)}")
        flash(f"{l['name']} assigned to {uname(na)}.", 'ok')
    return redirect(back(url_for('leads')))


@app.route('/leads/<int:lid>/delete', methods=['POST'])
@admin_required
def lead_delete(lid):
    get_lead(lid)
    x('DELETE FROM leads WHERE id=%s AND center_id=%s', (lid, cid()))
    flash('Lead deleted.', 'ok')
    return redirect(url_for('leads'))


@app.route('/leads/auto-assign', methods=['POST'])
@admin_required
def auto_assign():
    rows = q(f"""SELECT id FROM leads WHERE center_id=%s AND assigned_to IS NULL
                 AND stage IN ({ph(len(OPEN))})""", (cid(),) + tuple(OPEN))
    ids = active_counsellors()
    if not ids:
        flash('No active counsellors to assign to.', 'error')
        return redirect(url_for('leads'))
    names = counsellor_names()
    gen = round_robin(ids)
    for r in rows:
        c = next(gen)
        x('UPDATE leads SET assigned_to=%s WHERE id=%s', (c, r['id']))
        log(r['id'], 'System', f'Auto-assigned to {names[c]}')
    gen.close()
    flash(f'{len(rows)} leads assigned.', 'ok')
    return redirect(url_for('leads'))


@app.route('/leads/import', methods=['POST'])
@admin_required
def import_csv():
    f = request.files.get('file')
    if not f:
        flash('Choose a CSV file.', 'error')
        return redirect(url_for('leads'))
    try:
        text = f.read().decode('utf-8-sig')
    except UnicodeDecodeError:
        flash('Save the CSV as UTF-8 and try again.', 'error')
        return redirect(url_for('leads'))
    rows = list(csv.reader(io.StringIO(text)))
    if len(rows) < 2:
        flash('The CSV is empty.', 'error')
        return redirect(url_for('leads'))
    hd = [h.strip().lower() for h in rows[0]]

    def col(pred):
        return next((i for i, h in enumerate(hd) if pred(h)), -1)

    I = {'name': col(lambda h: 'name' in h and 'parent' not in h),
         'phone': col(lambda h: ('phone' in h or 'mobile' in h) and 'parent' not in h),
         'parent_phone': col(lambda h: 'parent' in h), 'course': col(lambda h: 'course' in h),
         'source': col(lambda h: 'source' in h), 'city': col(lambda h: h == 'city'),
         'target': col(lambda h: 'target' in h or h == 'class' or 'exam' in h),
         'email': col(lambda h: 'mail' in h),
         'stage': col(lambda h: 'stage' in h), 'counsellor': col(lambda h: 'counsel' in h),
         'created': col(lambda h: 'created' in h), 'next': col(lambda h: 'next' in h),
         'fee': col(lambda h: h in ('fee', 'total fee')), 'paid': col(lambda h: h == 'paid'),
         'lost': col(lambda h: 'lost' in h), 'activity': col(lambda h: 'activity' in h)}
    if I['name'] < 0 or I['phone'] < 0:
        flash('The CSV needs at least name and phone columns.', 'error')
        return redirect(url_for('leads'))

    stage_map = {s.lower(): s for s in STAGES}
    names = counsellor_names()
    by_name = {v.strip().lower(): k for k, v in names.items()}
    existing = {r['phone10'] for r in q('SELECT phone10 FROM leads WHERE center_id=%s', (cid(),))}
    gen = round_robin(active_counsellors())
    ok = skipped = 0

    def parse_dt(s):
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                pass
        return now()

    db().execute('BEGIN')
    try:
        for r in rows[1:5001]:
            def v(k, lim):
                i = I[k]
                return r[i].strip()[:lim] if 0 <= i < len(r) else ''

            d = {'name': v('name', 120), 'phone': v('phone', 20), 'parent_phone': v('parent_phone', 20),
                 'email': v('email', 120), 'city': v('city', 80), 'target': v('target', 120),
                 'course': v('course', 120) or (cfg()['courses'] or [''])[0],
                 'source': v('source', 80) or 'Import', 'notes': ''}
            p10 = phone10(d['phone'])
            if not d['name'] or len(p10) < 10 or p10 in existing:
                skipped += 1
                continue
            stage = stage_map.get(v('stage', 30).lower(), 'New')
            aid = by_name.get(v('counsellor', 100).lower()) or next(gen)
            created = parse_dt(v('created', 19))
            fee, paid = num(v('fee', 20)), num(v('paid', 20))
            if stage == 'Enrolled' and fee <= 0:
                stage = 'Negotiation'
            nf = (pdate(v('next', 10)) or today()) if stage in OPEN else None
            reason = (v('lost', 120) or 'Not recorded') if stage == 'Lost' else None

            lid = insert_lead(d, aid, nf)
            x('UPDATE leads SET stage=%s, fee=%s, paid=%s, lost_reason=%s, created_at=%s WHERE id=%s',
              (stage, fee if stage == 'Enrolled' else 0, min(paid, fee) if stage == 'Enrolled' else 0,
               reason, created, lid))
            log(lid, 'System', 'Imported from CSV' + (f', assigned to {names[aid]}' if aid else ''))
            act = v('activity', 2000)
            if act:
                x('INSERT INTO activities (lead_id, user_id, type, text, created_at) VALUES (%s,%s,%s,%s,%s)',
                  (lid, aid, 'Note', act, now()))
            existing.add(p10)
            ok += 1
        gen.close()
        db().execute('COMMIT')
    except Exception:
        db().execute('ROLLBACK')
        raise
    flash(f'{ok} leads imported, {skipped} skipped as duplicates or invalid.', 'ok')
    return redirect(url_for('leads'))


@app.route('/leads/export.csv')
@admin_required
def export_csv():
    rows = q("""SELECT l.*, u.name AS counsellor,
                (SELECT a.text FROM activities a WHERE a.lead_id=l.id ORDER BY a.id DESC LIMIT 1) AS last_activity
                FROM leads l LEFT JOIN users u ON u.id=l.assigned_to
                WHERE l.center_id=%s ORDER BY l.created_at DESC""", (cid(),))
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['Name', 'Phone', 'Parent phone', 'Email', 'City', 'Target', 'Course', 'Source', 'Stage',
                'Counsellor', 'Created', 'Next follow-up', 'Fee', 'Paid', 'Lost reason', 'Last activity'])
    for r in rows:
        w.writerow([csv_safe(r[k]) for k in ('name', 'phone', 'parent_phone', 'email', 'city', 'target',
                                             'course', 'source', 'stage', 'counsellor', 'created_at',
                                             'next_followup', 'fee', 'paid', 'lost_reason', 'last_activity')])
    return Response('\ufeff' + out.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=leads-{today()}.csv'})


@app.route('/followups')
@login_required
def followups():
    sc, sa = scope()
    t = today()
    rows = q(f"""SELECT l.*, u.name AS counsellor FROM leads l LEFT JOIN users u ON u.id=l.assigned_to
                 WHERE {sc} AND l.stage IN ({ph(len(OPEN))})
                 AND (l.next_followup IS NULL OR l.next_followup <= %s)
                 ORDER BY l.next_followup""", sa + tuple(OPEN) + (t + timedelta(days=7),))
    groups = [
        ('Overdue', [r for r in rows if r['next_followup'] and r['next_followup'] < t], 'Nothing overdue.'),
        ('Today', [r for r in rows if r['next_followup'] == t], 'No follow-ups scheduled today.'),
        ('Next 7 days', [r for r in rows if r['next_followup'] and r['next_followup'] > t], 'Nothing scheduled this week.'),
        ('No follow-up date', [r for r in rows if not r['next_followup']], 'Every open lead has a date.'),
    ]
    return render_template('followups.html', groups=groups)


# ---------- center team (managed by center admins only) ----------
def get_member(uid):
    u = q('SELECT * FROM users WHERE id=%s AND center_id=%s', (uid, cid()), one=True)
    if not u:
        abort(404)
    return u


@app.route('/team')
@admin_required
def team():
    users = q(f"""SELECT u.*,
        (SELECT COUNT(*) FROM leads l WHERE l.assigned_to=u.id) AS total,
        (SELECT COUNT(*) FROM leads l WHERE l.assigned_to=u.id AND l.stage IN ({ph(len(OPEN))})) AS open_leads,
        (SELECT COUNT(*) FROM leads l WHERE l.assigned_to=u.id AND l.stage='Enrolled') AS enrolled
        FROM users u WHERE u.center_id=%s
        ORDER BY u.is_primary DESC, u.role, u.active DESC, u.name""", tuple(OPEN) + (cid(),))
    return render_template('team.html', users=users)


@app.route('/team/create', methods=['POST'])
@admin_required
def user_create():
    f = request.form
    name, un, pw = f.get('name', '').strip()[:100], f.get('username', '').strip().lower(), f.get('password', '')
    role = f.get('role') if f.get('role') in ('admin', 'counsellor') else 'counsellor'
    err = validate_user(name, un, pw)
    if err:
        flash(err, 'error')
    else:
        x('INSERT INTO users (center_id, name, username, password_hash, role, is_primary, active, created_at) '
          'VALUES (%s,%s,%s,%s,%s,0,1,%s)', (cid(), name, un, generate_password_hash(pw), role, now()))
        flash(f'User {name} created. Share the username "{un}" and password privately.', 'ok')
    return redirect(url_for('team'))


@app.route('/team/<int:uid>/toggle', methods=['POST'])
@admin_required
def user_toggle(uid):
    u = get_member(uid)
    if u['is_primary']:
        flash('Main admins can only be changed by the super admin.', 'error')
    elif u['id'] == g.user['id']:
        flash("You can't deactivate yourself.", 'error')
    else:
        x('UPDATE users SET active=%s WHERE id=%s', (0 if u['active'] else 1, uid))
        flash(f"{u['name']} {'deactivated' if u['active'] else 'activated'}.", 'ok')
    return redirect(url_for('team'))


@app.route('/team/<int:uid>/reset', methods=['POST'])
@admin_required
def user_reset(uid):
    u = get_member(uid)
    if u['is_primary']:
        flash('Main admin passwords can only be reset by the super admin.', 'error')
        return redirect(url_for('team'))
    tmp = secrets.token_urlsafe(8)[:10]
    x('UPDATE users SET password_hash=%s WHERE id=%s', (generate_password_hash(tmp), uid))
    flash(f"Temporary password for {u['name']}: {tmp} — share it privately. They should change it under Account.", 'ok')
    return redirect(url_for('team'))


@app.route('/team/<int:uid>/move', methods=['POST'])
@admin_required
def user_move(uid):
    u = get_member(uid)
    rows = q(f"SELECT id FROM leads WHERE assigned_to=%s AND stage IN ({ph(len(OPEN))})", (uid,) + tuple(OPEN))
    ids = active_counsellors(skip=uid)
    if not ids:
        flash('No other active counsellors to receive these leads.', 'error')
        return redirect(url_for('team'))
    names = counsellor_names()
    gen = round_robin(ids)
    for r in rows:
        c = next(gen)
        x('UPDATE leads SET assigned_to=%s WHERE id=%s', (c, r['id']))
        log(r['id'], 'System', f"Reassigned from {u['name']} to {names[c]}")
    gen.close()
    flash(f"{len(rows)} open leads moved from {u['name']}.", 'ok')
    return redirect(url_for('team'))


# ---------- center settings and account ----------
@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    if request.method == 'POST':
        f = request.form

        def lst(k):
            return ', '.join(s.strip()[:120] for s in f.get(k, '').split(',') if s.strip())

        vals = {'inst': f.get('inst', '').strip()[:120], 'courses': lst('courses'), 'sources': lst('sources'),
                'lost_reasons': lst('lost_reasons'), 'wa_template': f.get('wa_template', '').strip()[:500]}
        if not all(vals.values()):
            flash('No setting can be empty.', 'error')
        else:
            for k, v in vals.items():
                set_cfg(k, v)
            flash('Settings saved.', 'ok')
        return redirect(url_for('settings'))
    return render_template('settings.html')


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        f = request.form
        if not check_password_hash(g.user['password_hash'], f.get('current', '')):
            flash('Current password is wrong.', 'error')
        elif len(f.get('new', '')) < 8:
            flash('New password needs at least 8 characters.', 'error')
        elif f.get('new') != f.get('confirm'):
            flash("New passwords don't match.", 'error')
        else:
            h = generate_password_hash(f['new'])
            x('UPDATE users SET password_hash=%s WHERE id=%s', (h, g.user['id']))
            session['pwv'] = h[-12:]
            flash('Password updated.', 'ok')
        return redirect(url_for('account'))
    return render_template('account.html')


# =====================================================================
#  WEBHOOKS — lead capture from Meta (Instagram + Facebook), Google Ads,
#  YouTube and website forms. Every channel feeds one ingest() pipeline.
# =====================================================================
GRAPH_VER = os.environ.get('GRAPH_VER', 'v23.0')
HOOK_HITS = {}
TEST_PREFIX = '00000'
CHANNELS = [('instagram', 'Instagram'), ('facebook', 'Facebook'), ('google', 'Google Ads'),
            ('youtube', 'YouTube'), ('website', 'Website')]
CHANNEL_NAMES = dict(CHANNELS)
WH_TABS = [('overview', 'Overview'), ('meta', 'Meta setup')] + CHANNELS
TEST_SOURCES = {'instagram': 'Instagram Ads', 'facebook': 'Facebook Ads', 'google': 'Google Ads',
                'youtube': 'YouTube Ads', 'website': 'Website'}
UTM_CHANNEL = {'instagram': ('instagram', 'Instagram'), 'ig': ('instagram', 'Instagram'),
               'facebook': ('facebook', 'Facebook'), 'fb': ('facebook', 'Facebook'),
               'youtube': ('youtube', 'YouTube'), 'yt': ('youtube', 'YouTube'),
               'google': ('website', 'Google'), 'whatsapp': ('website', 'WhatsApp')}
FIELD_LIMITS = {'name': 120, 'phone': 20, 'parent_phone': 20, 'email': 120, 'city': 80,
                'target': 120, 'course': 120, 'source': 80, 'notes': 2000}
ALIASES = {
    'name': ('full_name', 'name', 'student_name', 'fullname', 'your_name'),
    'phone': ('phone_number', 'phone', 'mobile', 'mobile_number', 'whatsapp_number', 'contact_number'),
    'parent_phone': ('parent_phone', 'parents_phone', 'guardian_phone', 'father_phone', 'parent_mobile'),
    'email': ('email', 'email_address', 'work_email'),
    'city': ('city', 'location', 'town'),
    'course': ('course', 'course_interested', 'program', 'programme',
               'which_course_are_you_interested_in'),
    'target': ('target', 'class', 'exam', 'grade', 'current_class'),
}
IGNORE_KEYS = {'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
               'fbclid', 'gclid', 'website', '_csrf'}


def normalize(fields):
    f = {re.sub(r'[^a-z0-9]+', '_', str(k).lower()).strip('_'): str(v).strip()
         for k, v in fields.items() if v not in (None, '')}
    d, used = {}, set(IGNORE_KEYS)
    for key, names in ALIASES.items():
        for n in names:
            if f.get(n):
                d[key] = f[n]
                used.add(n)
                break
    if 'name' not in d:
        full = ' '.join(filter(None, (f.get('first_name'), f.get('last_name'))))
        if full:
            d['name'] = full
            used |= {'first_name', 'last_name'}
    extra = [f"{k.replace('_', ' ')}: {v}" for k, v in f.items() if k not in used]
    return d, extra


def match_course(v):
    v = (v or '').strip()
    low = v.lower().replace('_', ' ')
    if not low:
        return ''
    courses = cfg()['courses']
    for c in courses:
        if c.lower() == low:
            return c
    if len(low) >= 3:
        for c in courses:
            if c.lower() in low or low in c.lower():
                return c
    return v


def integ(center):
    r = q('SELECT * FROM integrations WHERE center_id=%s', (center,), one=True)
    if not r:
        x('INSERT OR IGNORE INTO integrations (center_id, token, meta_verify, updated_at) VALUES (%s,%s,%s,%s)',
          (center, secrets.token_hex(16), secrets.token_urlsafe(24), now()))
        r = q('SELECT * FROM integrations WHERE center_id=%s', (center,), one=True)
    return r


def integ_by_token(token):
    if not re.fullmatch(r'[0-9a-f]{32}', token or ''):
        abort(404)
    r = q('SELECT i.*, c.active AS center_active, c.active_until FROM integrations i '
          'JOIN centers c ON c.id=i.center_id WHERE i.token=%s', (token,), one=True)
    if not r:
        abort(404)
    return r


def ingest(center_id, provider, channel, ext_id, fields, source, context, raw, enabled=True, test=False):
    """Single entry point for every channel. Returns (status, lead_id)."""
    prev = g.get('user')
    g.user = {'id': None, 'name': 'System', 'role': 'system', 'center_id': center_id}
    g.pop('cfg', None)
    conn = db()
    conn.execute('BEGIN IMMEDIATE')  # serialises round-robin across simultaneous deliveries
    try:
        result = _ingest(center_id, provider, channel, ext_id, fields, source, context, raw, enabled, test)
        conn.execute('COMMIT')
        return result
    except Exception:
        conn.execute('ROLLBACK')
        raise
    finally:
        g.user = prev
        g.pop('cfg', None)


def _ingest(center_id, provider, channel, ext_id, fields, source, context, raw, enabled, test):
    try:
        iid = x('INSERT INTO inbound (center_id, provider, channel, ext_id, status, payload, created_at) '
                'VALUES (%s,%s,%s,%s,%s,%s,%s)',
                (center_id, provider, channel, str(ext_id)[:120], 'received',
                 json.dumps(raw, default=str, ensure_ascii=False)[:200000], now()))
    except sqlite3.IntegrityError:
        return 'duplicate', None
    if secrets.randbelow(200) == 0:
        x('DELETE FROM inbound WHERE created_at < %s', (now() - timedelta(days=90),))

    def done(status, lid=None, detail=None):
        x('UPDATE inbound SET status=%s, lead_id=%s, detail=%s WHERE id=%s',
          (status, lid, (detail or '')[:500] or None, iid))
        return status, lid

    c = q('SELECT active, active_until FROM centers WHERE id=%s', (center_id,), one=True)
    if not c or not c['active'] or c['active_until'] < today():
        return done('center_closed', detail='Center access is suspended or expired.')
    if not enabled:
        return done('disabled', detail=f'{CHANNEL_NAMES.get(channel, channel)} capture is switched off.')

    d, extra = normalize(fields)
    if test:
        d['name'] = f'TEST lead · {source}'
        d['phone'] = TEST_PREFIX + f'{secrets.randbelow(10 ** 5):05d}'
    p10 = phone10(d.get('phone'))
    if not d.get('name'):
        return done('invalid', detail='No name in the submission.')
    if len(p10) < 10:
        return done('invalid', detail='No valid 10-digit phone number in the submission.')

    d['course'] = match_course(d.get('course'))
    d['source'] = source
    info = ' · '.join(filter(None, [context] + extra))[:1500]

    dup = q('SELECT id, stage FROM leads WHERE center_id=%s AND phone10=%s', (center_id, p10), one=True)
    if dup:
        if dup['stage'] == 'Lost':
            x("UPDATE leads SET stage='New', lost_reason=NULL, next_followup=%s WHERE id=%s", (today(), dup['id']))
            log(dup['id'], 'System', f'Re-enquiry via {source}. Reopened from Lost. {info}'.strip()[:2000])
        elif dup['stage'] in OPEN:
            x('UPDATE leads SET next_followup=%s WHERE id=%s', (today(), dup['id']))
            log(dup['id'], 'System', f'Re-enquiry via {source}. Follow-up moved to today. {info}'.strip()[:2000])
        else:
            log(dup['id'], 'System', f'Enquiry via {source} from an enrolled student. {info}'.strip()[:2000])
        return done('merged', dup['id'], f"Existing lead (stage was {dup['stage']})")

    d['notes'] = '\n'.join(extra)
    d = {k: (d.get(k) or '')[:lim] for k, lim in FIELD_LIMITS.items()}
    aid = None if test else next_counsellor()
    try:
        lid = insert_lead(d, aid, today())
    except sqlite3.IntegrityError:
        return done('merged', detail='Added by a parallel delivery.')
    log(lid, 'System', (f'Captured from {source}' + (f', assigned to {uname(aid)}' if aid else '')
                        + (f'. {context}' if context else ''))[:2000])
    return done('test' if test else 'created', lid,
                f'Assigned to {uname(aid)}' if aid else 'Unassigned')


def hook_rate_ok(limit=20, window=600):
    ip = (request.headers.get('X-Forwarded-For') or request.remote_addr or '').split(',')[0].strip()
    hits = [t for t in HOOK_HITS.get(ip, []) if time.time() - t < window]
    hits.append(time.time())
    HOOK_HITS[ip] = hits
    return len(hits) <= limit


def cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp


def graph(path, token=None, method='GET', **params):
    if token:
        params['access_token'] = token
    url = f'https://graph.facebook.com/{GRAPH_VER}/{path}'
    body = None
    if method == 'GET':
        url += '?' + urlencode(params)
    else:
        body = urlencode(params).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=body, method=method), timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get('error', {}).get('message', str(e))
        except ValueError:
            msg = str(e)
        raise RuntimeError(msg)
    except urllib.error.URLError as e:
        raise RuntimeError(f'Could not reach Meta: {e.reason}')


def meta_process(it, page, leadgen_id):
    """Fetch one Meta lead and ingest it. Failures are parked for the Retry button."""
    center = it['center_id']
    try:
        lead = graph(leadgen_id, dec(page['token']),
                     fields='field_data,platform,campaign_name,ad_name,form_id,created_time')
    except RuntimeError as e:
        x('INSERT INTO inbound (center_id, provider, channel, ext_id, status, detail, payload, created_at) '
          'VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(center_id, provider, ext_id) '
          'DO UPDATE SET detail=excluded.detail, created_at=excluded.created_at',
          (center, 'meta-fail', 'meta', leadgen_id, 'fetch_failed', str(e)[:500],
           json.dumps({'page_id': page['page_id'], 'leadgen_id': leadgen_id}), now()))
        return False
    fields = {fd.get('name', ''): ', '.join(fd.get('values', [])) for fd in lead.get('field_data', [])}
    channel = 'instagram' if lead.get('platform') == 'ig' else 'facebook'
    source = 'Instagram Ads' if channel == 'instagram' else 'Facebook Ads'
    ctx_text = ' / '.join(filter(None, [lead.get('campaign_name'), lead.get('ad_name')]))
    ingest(center, 'meta', channel, leadgen_id, fields, source, ctx_text, lead,
           enabled=bool(it[f'ch_{channel}']))
    x("DELETE FROM inbound WHERE center_id=%s AND provider='meta-fail' AND ext_id=%s", (center, leadgen_id))
    return True


# ---------- public webhook endpoints ----------
@app.route('/hook/<token>/meta', methods=['GET', 'POST'])
def hook_meta(token):
    it = integ_by_token(token)
    if request.method == 'GET':
        if request.args.get('hub.mode') == 'subscribe' and \
                secrets.compare_digest(request.args.get('hub.verify_token', ''), it['meta_verify']):
            return request.args.get('hub.challenge', ''), 200
        abort(403)
    secret = dec(it['meta_app_secret'])
    expected = 'sha256=' + hmac.new(secret.encode(), request.get_data(), hashlib.sha256).hexdigest()
    if not secret or not hmac.compare_digest(request.headers.get('X-Hub-Signature-256', ''), expected):
        abort(403)
    for entry in (request.get_json(silent=True) or {}).get('entry', []):
        for ch in entry.get('changes', []):
            if ch.get('field') != 'leadgen':
                continue
            v = ch.get('value') or {}
            lgid, pid = str(v.get('leadgen_id') or ''), str(v.get('page_id') or '')
            if not lgid:
                continue
            page = q('SELECT * FROM meta_pages WHERE center_id=%s AND page_id=%s',
                     (it['center_id'], pid), one=True)
            if not page:
                continue
            if q("SELECT 1 FROM inbound WHERE center_id=%s AND provider='meta' AND ext_id=%s",
                 (it['center_id'], lgid), one=True):
                continue
            meta_process(it, page, lgid)
    return 'ok', 200


@app.route('/hook/<token>/google', methods=['POST'])
def hook_google(token):
    it = integ_by_token(token)
    data = request.get_json(silent=True) or {}
    key = dec(it['google_key'])
    if not key or not secrets.compare_digest(str(data.get('google_key', '')), key):
        abort(403)
    fields = {(c.get('column_name') or c.get('column_id') or ''): c.get('string_value')
              for c in data.get('user_column_data', []) if isinstance(c, dict)}
    form_id = str(data.get('form_id') or '')
    yt_forms = {s.strip() for s in (it['youtube_forms'] or '').split(',') if s.strip()}
    is_yt = bool(form_id) and form_id in yt_forms
    channel, source = ('youtube', 'YouTube Ads') if is_yt else ('google', 'Google Ads')
    is_test = bool(data.get('is_test'))
    ext = str(data.get('lead_id') or secrets.token_hex(12))
    if is_test:
        ext = f'gtest-{ext}-{secrets.token_hex(4)}'
    ctx_text = f"form {form_id} · campaign {data.get('campaign_id', '')}"
    ingest(it['center_id'], 'google', channel, ext, fields, source, ctx_text, data,
           enabled=bool(it[f'ch_{channel}']), test=is_test)
    return jsonify({}), 200


@app.route('/hook/<token>/web', methods=['POST', 'OPTIONS'])
def hook_web(token):
    if request.method == 'OPTIONS':
        return cors(Response(status=204))
    it = integ_by_token(token)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form.to_dict()
    data = {str(k)[:60]: str(v)[:2000] for k, v in list(data.items())[:40]}
    if data.get('website'):  # honeypot field: only bots fill it
        return cors(jsonify(ok=True))
    if not hook_rate_ok():
        return cors(jsonify(ok=False, error='Too many submissions. Try again in a few minutes.')), 429
    utm = data.get('utm_source', '').strip().lower()
    channel, source = UTM_CHANNEL.get(utm, ('website', 'Website'))
    ctx_text = ' '.join(f'{k}={data[k]}' for k in ('utm_medium', 'utm_campaign') if data.get(k))
    status, _ = ingest(it['center_id'], 'web', channel, secrets.token_hex(12), data, source, ctx_text, data,
                       enabled=bool(it['ch_website']))
    if status in ('created', 'merged'):
        return cors(jsonify(ok=True))
    msg = 'Enter your name and a valid 10-digit mobile number.' if status == 'invalid' \
        else 'Enquiries are closed right now. Please call us directly.'
    return cors(jsonify(ok=False, error=msg)), 422


@app.route('/f/<token>')
def public_form(token):
    it = integ_by_token(token)
    s = {r['k']: r['v'] for r in q('SELECT k, v FROM settings WHERE center_id=%s', (it['center_id'],))}
    courses = [c.strip() for c in (s.get('courses') or DEFAULTS['courses']).split(',') if c.strip()]
    is_open = bool(it['center_active']) and it['active_until'] >= today() and bool(it['ch_website'])
    return render_template('public_form.html', inst=s.get('inst') or DEFAULTS['inst'], courses=courses,
                           post_url=url_for('hook_web', token=token), is_open=is_open)


# ---------- admin: Webhooks tab ----------
def public_base():
    b = (os.environ.get('PUBLIC_URL') or '').strip().rstrip('/')
    if b:
        return b
    root = request.url_root.rstrip('/')
    if root.startswith('http://') and app.config['SESSION_COOKIE_SECURE']:
        root = 'https://' + root[len('http://'):]
    return root


def wh_action(it, act, f):
    center = cid()
    if act == 'toggle':
        ch = f.get('channel')
        if ch in CHANNEL_NAMES:
            col = f'ch_{ch}'
            x(f'UPDATE integrations SET {col}=%s, updated_at=%s WHERE center_id=%s',
              (0 if it[col] else 1, now(), center))
            flash(f"{CHANNEL_NAMES[ch]} capture switched {'off' if it[col] else 'on'}.", 'ok')

    elif act == 'meta_app':
        app_id = re.sub(r'\D', '', f.get('meta_app_id', ''))[:30]
        secret = f.get('meta_app_secret', '').strip()
        if not app_id:
            flash('Enter the Meta App ID (numbers only).', 'error')
        elif secret and not re.fullmatch(r'[A-Za-z0-9]{20,64}', secret):
            flash('That App Secret does not look right. Copy it again from Settings > Basic.', 'error')
        elif not secret and not dec(it['meta_app_secret']):
            flash('Enter the App Secret.', 'error')
        else:
            x('UPDATE integrations SET meta_app_id=%s, meta_app_secret=%s, updated_at=%s WHERE center_id=%s',
              (app_id, enc(secret) if secret else it['meta_app_secret'], now(), center))
            flash('Meta app details saved.', 'ok')

    elif act == 'meta_verify':
        x('UPDATE integrations SET meta_verify=%s WHERE center_id=%s', (secrets.token_urlsafe(24), center))
        flash('New verify token created. Update it in the Meta app Webhooks settings.', 'ok')

    elif act == 'meta_connect':
        user_tok = f.get('user_token', '').strip()
        want = re.sub(r'\D', '', f.get('page_id', ''))
        secret = dec(it['meta_app_secret'])
        if not it['meta_app_id'] or not secret:
            flash('Save the App ID and App Secret first.', 'error')
            return
        if not user_tok:
            flash('Paste the user access token from Graph API Explorer.', 'error')
            return
        try:
            ll = graph('oauth/access_token', grant_type='fb_exchange_token', client_id=it['meta_app_id'],
                       client_secret=secret, fb_exchange_token=user_tok)['access_token']
            pages = graph('me/accounts', ll, fields='id,name,access_token', limit=100).get('data', [])
        except (RuntimeError, KeyError) as e:
            flash(f'Meta rejected the token: {e}', 'error')
            return
        if want:
            pages = [p for p in pages if p.get('id') == want]
        if not pages:
            flash('No matching Facebook page found for this token. Check the page ID and the '
                  'pages you selected when generating the token.', 'error')
            return
        linked, failed = [], []
        for p in pages:
            try:
                graph(f"{p['id']}/subscribed_apps", p['access_token'], method='POST', subscribed_fields='leadgen')
            except RuntimeError as e:
                failed.append(f"{p.get('name', p['id'])}: {e}")
                continue
            x('INSERT INTO meta_pages (center_id, page_id, name, token, created_at) VALUES (%s,%s,%s,%s,%s) '
              'ON CONFLICT(center_id, page_id) DO UPDATE SET name=excluded.name, token=excluded.token',
              (center, p['id'], p.get('name', '')[:120], enc(p['access_token']), now()))
            linked.append(p.get('name', p['id']))
        if linked:
            flash(f"Linked: {', '.join(linked)}.", 'ok')
        if failed:
            flash('Not linked: ' + ' | '.join(failed), 'error')

    elif act == 'meta_unlink':
        x('DELETE FROM meta_pages WHERE center_id=%s AND page_id=%s', (center, f.get('page_id', '')))
        flash('Page unlinked.', 'ok')

    elif act == 'meta_check':
        pages = q('SELECT * FROM meta_pages WHERE center_id=%s', (center,))
        if not pages:
            flash('No pages linked yet.', 'error')
            return
        good, msgs = True, []
        for p in pages:
            label = p['name'] or p['page_id']
            try:
                subs = graph(f"{p['page_id']}/subscribed_apps", dec(p['token'])).get('data', [])
                ok = any(str(s.get('id')) == str(it['meta_app_id']) and 'leadgen' in (s.get('subscribed_fields') or [])
                         for s in subs)
                msgs.append(f'{label}: working' if ok else f'{label}: not subscribed to leads. Reconnect it.')
                good = good and ok
            except RuntimeError as e:
                msgs.append(f'{label}: token rejected ({e}). Reconnect it.')
                good = False
        flash(' | '.join(msgs), 'ok' if good else 'error')

    elif act == 'meta_retry':
        rows = q("SELECT ext_id, payload FROM inbound WHERE center_id=%s AND provider='meta-fail'", (center,))
        done_n = 0
        for r in rows:
            pid = json.loads(r['payload']).get('page_id', '')
            page = q('SELECT * FROM meta_pages WHERE center_id=%s AND page_id=%s', (center, pid), one=True)
            if page and meta_process(it, page, r['ext_id']):
                done_n += 1
        flash(f'{done_n} of {len(rows)} failed Meta leads recovered.', 'ok' if done_n == len(rows) else 'error')

    elif act == 'google_key':
        x('UPDATE integrations SET google_key=%s, updated_at=%s WHERE center_id=%s',
          (enc(secrets.token_urlsafe(24)), now(), center))
        flash('New Google key generated. Paste it into every Google Ads lead form webhook.', 'ok')

    elif act == 'youtube_forms':
        ids = ','.join(dict.fromkeys(re.findall(r'\d+', f.get('youtube_forms', ''))))
        x('UPDATE integrations SET youtube_forms=%s, updated_at=%s WHERE center_id=%s', (ids or None, now(), center))
        flash('YouTube form IDs saved.', 'ok')

    elif act == 'rotate':
        x('UPDATE integrations SET token=%s, updated_at=%s WHERE center_id=%s', (secrets.token_hex(16), now(), center))
        flash('All webhook URLs changed. Old URLs are dead. Update Meta, Google Ads, your website and bio links.', 'ok')

    elif act == 'test':
        ch = f.get('channel')
        if ch in CHANNEL_NAMES:
            sample = {'full_name': 'Test', 'phone_number': '', 'email': 'test@example.com', 'city': 'Test city',
                      'course': (cfg()['courses'] or [''])[0]}
            status, lid = ingest(center, 'test', ch, f'test-{secrets.token_hex(8)}', sample, TEST_SOURCES[ch],
                                 'Sent from the Webhooks page', {'test': True}, test=True)
            flash(f'Test lead result: {status}.' + (' It is unassigned and named "TEST lead".' if lid else ''),
                  'ok' if lid else 'error')

    elif act == 'delete_tests':
        n = q("SELECT COUNT(*) AS n FROM leads WHERE center_id=%s AND phone10 LIKE %s AND name LIKE 'TEST lead%'",
              (center, TEST_PREFIX + '%'), one=True)['n']
        x("DELETE FROM leads WHERE center_id=%s AND phone10 LIKE %s AND name LIKE 'TEST lead%'",
          (center, TEST_PREFIX + '%'))
        flash(f'{n} test leads deleted.', 'ok')


@app.route('/webhooks', methods=['GET', 'POST'])
@admin_required
def webhooks():
    it = integ(cid())
    tab = request.args.get('tab', 'overview')
    if tab not in dict(WH_TABS):
        tab = 'overview'
    if request.method == 'POST':
        wh_action(it, request.form.get('action', ''), request.form)
        return redirect(url_for('webhooks', tab=tab))

    pages = q('SELECT page_id, name, created_at FROM meta_pages WHERE center_id=%s ORDER BY name', (cid(),))
    if tab in CHANNEL_NAMES:
        lw, la = "channel=%s AND provider<>'meta-fail'", (tab,)
    elif tab == 'meta':
        lw, la = "provider IN ('meta','meta-fail')", ()
    else:
        lw, la = '1=1', ()
    logs = q(f'SELECT id, provider, channel, status, detail, lead_id, created_at FROM inbound '
             f'WHERE center_id=%s AND {lw} ORDER BY id DESC LIMIT 50', (cid(),) + la)
    stats = {r['channel']: r for r in q(
        """SELECT channel, COUNT(*) AS n, COALESCE(SUM(status='created'),0) AS created,
           COALESCE(SUM(status='merged'),0) AS merged,
           COALESCE(SUM(status IN ('invalid','disabled','center_closed')),0) AS problems,
           MAX(created_at) AS last FROM inbound
           WHERE center_id=%s AND provider NOT IN ('test','meta-fail') AND created_at >= %s GROUP BY channel""",
        (cid(), now() - timedelta(days=30)))}
    failed = q("SELECT COUNT(*) AS n FROM inbound WHERE center_id=%s AND provider='meta-fail'",
               (cid(),), one=True)['n']
    tests = q("SELECT COUNT(*) AS n FROM leads WHERE center_id=%s AND phone10 LIKE %s AND name LIKE 'TEST lead%'",
              (cid(), TEST_PREFIX + '%'), one=True)['n']
    google_key = dec(it['google_key'])
    has_secret = bool(dec(it['meta_app_secret']))
    meta_ready = bool(it['meta_app_id'] and has_secret and pages)
    connected = {'instagram': meta_ready, 'facebook': meta_ready, 'google': bool(google_key),
                 'youtube': bool(google_key and it['youtube_forms']), 'website': True}
    b, tok = public_base(), it['token']
    urls = {'meta': f'{b}/hook/{tok}/meta', 'google': f'{b}/hook/{tok}/google',
            'web': f'{b}/hook/{tok}/web', 'form': f'{b}/f/{tok}'}
    return render_template('webhooks.html', tab=tab, tabs=WH_TABS, channels=CHANNELS, names=CHANNEL_NAMES,
                           it=it, pages=pages, logs=logs, stats=stats, failed=failed, tests=tests,
                           google_key=google_key, has_secret=has_secret, meta_ready=meta_ready,
                           connected=connected, urls=urls)


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')
