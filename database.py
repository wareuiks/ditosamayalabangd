import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL', '').strip()
DB_PATH = os.path.join(os.path.dirname(__file__), 'shop.db')
LEGACY_SALT = "ovk_secure_salt_2026"


def is_postgres() -> bool:
    url = os.getenv('DATABASE_URL', DATABASE_URL).strip()
    return bool(url and (url.startswith('postgres://') or url.startswith('postgresql://')))


class PgCursorWrapper:
    def __init__(self, pg_cursor):
        self.cursor = pg_cursor
        self.lastrowid = None

    def execute(self, query, params=None):
        clean_query = query.replace('%', '%%').replace('?', '%s')
        upper_q = clean_query.strip().upper()
        is_insert = upper_q.startswith('INSERT INTO')
        has_returning = 'RETURNING' in upper_q

        if is_insert and not has_returning and 'INTO SETTINGS' not in upper_q:
            clean_query = clean_query.rstrip().rstrip(';') + ' RETURNING id;'

        if params is not None:
            if isinstance(params, (list, tuple)):
                self.cursor.execute(clean_query, params)
            else:
                self.cursor.execute(clean_query, (params,))
        else:
            self.cursor.execute(clean_query)

        if is_insert and not has_returning and 'INTO SETTINGS' not in upper_q:
            try:
                res = self.cursor.fetchone()
                if res:
                    self.lastrowid = res['id'] if isinstance(res, dict) else res[0]
            except Exception:
                pass
        return self

    def executemany(self, query, params_list):
        clean_query = query.replace('%', '%%').replace('?', '%s')
        return self.cursor.executemany(clean_query, params_list)

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def close(self):
        return self.cursor.close()

    @property
    def rowcount(self):
        return getattr(self.cursor, 'rowcount', 0)

    def __getattr__(self, name):
        return getattr(self.cursor, name)

    def __iter__(self):
        return iter(self.cursor)


class PgConnectionWrapper:
    def __init__(self, pg_conn):
        self.conn = pg_conn

    def cursor(self):
        import psycopg2.extras
        cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return PgCursorWrapper(cur)

    def commit(self):
        return self.conn.commit()

    def rollback(self):
        return self.conn.rollback()

    def close(self):
        return self.conn.close()


def get_db():
    if is_postgres():
        import psycopg2
        raw_url = os.getenv('DATABASE_URL', DATABASE_URL).strip()
        url = raw_url.replace('[', '').replace(']', '')
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        conn = psycopg2.connect(url)
        return PgConnectionWrapper(conn)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return generate_password_hash(password, method='scrypt')


def verify_password(stored_hash: str, password: str) -> tuple[bool, bool]:
    """Verify password against scrypt/pbkdf2 or legacy SHA-256. Returns (valid, needs_rehash)."""
    if not stored_hash or not password:
        return False, False
    if stored_hash.startswith(('scrypt:', 'pbkdf2:')):
        try:
            return check_password_hash(stored_hash, password), False
        except Exception:
            return False, False
    legacy = hashlib.sha256((password + LEGACY_SALT).encode('utf-8')).hexdigest()
    valid = hmac.compare_digest(stored_hash, legacy)
    return valid, valid


def generate_referral_code(cursor) -> str:
    for _ in range(32):
        code = uuid.uuid4().hex[:8].upper()
        cursor.execute('SELECT id FROM users WHERE referral_code = ?', (code,))
        if not cursor.fetchone():
            return code
    return uuid.uuid4().hex[:10].upper()


def _ensure_column(cursor, table: str, column: str, ddl: str):
    if is_postgres():
        cursor.execute(
            'SELECT column_name FROM information_schema.columns WHERE table_name = ?',
            (table,)
        )
        cols = {row['column_name'] if isinstance(row, dict) else row[0] for row in cursor.fetchall()}
    else:
        cursor.execute(f'PRAGMA table_info({table})')
        cols = {row['name'] if isinstance(row, dict) or hasattr(row, 'keys') else row[1] for row in cursor.fetchall()}
    if column not in cols:
        cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column} {ddl}')


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    pk_type = "SERIAL PRIMARY KEY" if is_postgres() else "INTEGER PRIMARY KEY AUTOINCREMENT"

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS users (
        id {pk_type},
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        balance REAL DEFAULT 0.0,
        role TEXT DEFAULT 'user',
        referral_code TEXT,
        referred_by INTEGER,
        referral_earnings REAL DEFAULT 0,
        is_banned INTEGER DEFAULT 0,
        ban_reason TEXT,
        session_version INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS catalog_items (
        id {pk_type},
        title TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'GAMES',
        platform TEXT NOT NULL DEFAULT 'ANDROID',
        image_url TEXT NOT NULL,
        description TEXT,
        is_active INTEGER DEFAULT 1
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS products (
        id {pk_type},
        catalog_id INTEGER DEFAULT 1,
        name TEXT NOT NULL,
        duration TEXT NOT NULL,
        price REAL NOT NULL,
        badge TEXT,
        features TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (catalog_id) REFERENCES catalog_items (id)
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS license_keys (
        id {pk_type},
        product_id INTEGER NOT NULL,
        license_key TEXT UNIQUE NOT NULL,
        is_used INTEGER DEFAULT 0,
        assigned_to_user_id INTEGER DEFAULT NULL,
        used_at TIMESTAMP DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products (id),
        FOREIGN KEY (assigned_to_user_id) REFERENCES users (id)
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS orders (
        id {pk_type},
        order_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name TEXT NOT NULL,
        price REAL NOT NULL,
        license_key TEXT NOT NULL,
        voucher_code TEXT,
        discount_amount REAL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (product_id) REFERENCES products (id)
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS transactions (
        id {pk_type},
        reference_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount REAL NOT NULL,
        status TEXT NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS security_events (
        id {pk_type},
        ip TEXT,
        kind TEXT NOT NULL,
        path TEXT,
        user_agent TEXT,
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS ledger_entries (
        id {pk_type},
        entry_type TEXT NOT NULL,
        amount REAL NOT NULL,
        category TEXT DEFAULT 'general',
        note TEXT,
        occurred_on TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS fund_adjustments (
        id {pk_type},
        admin_user TEXT NOT NULL,
        amount REAL NOT NULL,
        adjustment_type TEXT NOT NULL,
        target_user_id INTEGER,
        target_username TEXT,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS referral_rewards (
        id {pk_type},
        referrer_id INTEGER NOT NULL,
        referred_user_id INTEGER NOT NULL,
        order_id TEXT NOT NULL,
        order_amount REAL NOT NULL,
        percent REAL NOT NULL,
        reward REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS vouchers (
        id {pk_type},
        code TEXT UNIQUE NOT NULL,
        discount_percent INTEGER NOT NULL,
        tier_scope TEXT NOT NULL DEFAULT 'lifetime',
        max_uses INTEGER NOT NULL DEFAULT 1,
        used_count INTEGER NOT NULL DEFAULT 0,
        per_user_limit INTEGER NOT NULL DEFAULT 1,
        expires_at TEXT DEFAULT NULL,
        note TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS voucher_usages (
        id {pk_type},
        voucher_id INTEGER NOT NULL,
        voucher_code TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        order_id TEXT NOT NULL,
        original_price REAL NOT NULL,
        discount_amount REAL NOT NULL,
        final_price REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id {pk_type},
        admin_user TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT,
        ip TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute(f'''
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id {pk_type},
        ip TEXT UNIQUE NOT NULL,
        reason TEXT,
        blocked_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    _ensure_column(cursor, 'users', 'referral_code', 'TEXT')
    _ensure_column(cursor, 'users', 'referred_by', 'INTEGER')
    _ensure_column(cursor, 'users', 'referral_earnings', 'REAL DEFAULT 0')
    _ensure_column(cursor, 'users', 'is_banned', 'INTEGER DEFAULT 0')
    _ensure_column(cursor, 'users', 'ban_reason', 'TEXT')
    _ensure_column(cursor, 'users', 'session_version', 'INTEGER DEFAULT 1')
    _ensure_column(cursor, 'orders', 'voucher_code', 'TEXT')
    _ensure_column(cursor, 'orders', 'discount_amount', 'REAL DEFAULT 0')

    for s_key, s_val in [('referral_enabled', '1'), ('referral_percent', '5')]:
        cursor.execute('SELECT key FROM settings WHERE key = ?', (s_key,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO settings (key, value) VALUES (?, ?)', (s_key, s_val))

    cursor.execute("SELECT id FROM users WHERE referral_code IS NULL OR referral_code = ''")
    for u_row in cursor.fetchall():
        uid = u_row['id'] if isinstance(u_row, dict) or hasattr(u_row, 'keys') else u_row[0]
        cursor.execute('UPDATE users SET referral_code = ? WHERE id = ?', (generate_referral_code(cursor), uid))

    conn.commit()

    cursor.execute('SELECT COUNT(*) as count FROM catalog_items')
    res = cursor.fetchone()
    count = res['count'] if isinstance(res, dict) or hasattr(res, 'keys') else res[0]
    if count == 0:
        cursor.execute('''
            INSERT INTO catalog_items (title, category, platform, image_url, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            'OVK Premium - CODMGR',
            'GAMES',
            'ANDROID',
            '/static/images/product1.jpg',
            'Undetected CODM aimbot, wallhack & ESP. Instant key delivery right after payment.'
        ))
        item1_id = cursor.lastrowid or 1

        tiers = [
            ('3 DAYS', 70.0, 'Trial Tier', ['3 Days Access', 'Undetected Bypass', 'Instant Key Delivery', 'Auto Loader']),
            ('7 DAYS', 100.0, 'Popular', ['7 Days Access', 'Undetected Bypass', 'Instant Key Delivery', '1x HWID Reset']),
            ('14 DAYS', 150.0, 'Great Value', ['14 Days Access', 'Undetected Bypass', 'Instant Key Delivery', '2x HWID Reset']),
            ('30 DAYS', 250.0, 'Best Seller', ['30 Days Access', 'Undetected Bypass', 'Instant Key Delivery', 'Unlimited HWID Reset']),
            ('60 DAYS', 320.0, 'Pro Choice', ['60 Days Access', 'Undetected Bypass', 'Instant Key Delivery', 'Priority 0-Day Builds']),
            ('LIFETIME', 700.0, 'Ultimate Value', ['Lifetime Forever Access', 'All Future Updates', 'Instant Key Delivery', 'Direct VIP Support'])
        ]

        for dur, price, badge, feat in tiers:
            cursor.execute('''
                INSERT INTO products (catalog_id, name, duration, price, badge, features)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (item1_id, f"OVK Premium - {dur}", dur, price, badge, json.dumps(feat)))

        conn.commit()

    cursor.execute('SELECT COUNT(*) as count FROM users')
    res_users = cursor.fetchone()
    users_count = res_users['count'] if isinstance(res_users, dict) or hasattr(res_users, 'keys') else res_users[0]
    if users_count == 0:
        ref_code = generate_referral_code(cursor)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, balance, role, referral_code)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('admin', 'admin@ovk.local', hash_password('Rovic1925#'), 0.0, 'admin', ref_code))
        conn.commit()

    conn.close()


if __name__ == '__main__':
    init_db()
    print("Database schema initialized and verified.")
