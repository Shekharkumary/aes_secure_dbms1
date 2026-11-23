"""AES-256-GCM encrypted SQLite database (core module)."""
import sqlite3
import time
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

FIELDS = ("full_name", "email", "phone", "card_number", "notes")
NONCE, TAG = 12, 16
MAX_ATTEMPTS, LOCKOUT_SECONDS = 5, 30


class AuthError(Exception):
    pass


class IntegrityError(Exception):
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    """Password -> 256-bit key using scrypt (memory-hard KDF)."""
    return scrypt(password.encode(), salt, 32, N=2**15, r=8, p=1)


def encrypt(key: bytes, text: str, aad: bytes) -> bytes:
    nonce = get_random_bytes(NONCE)                 # fresh random nonce per value
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(text.encode())
    return nonce + tag + ct


def decrypt(key: bytes, blob: bytes, aad: bytes) -> str:
    nonce, tag, ct = blob[:NONCE], blob[NONCE:NONCE + TAG], blob[NONCE + TAG:]
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(aad)
    try:
        return c.decrypt_and_verify(ct, tag).decode()
    except ValueError as e:                          # wrong key or tampered data
        raise IntegrityError("Decryption failed: wrong key or tampered data") from e


class SecureDB:
    def __init__(self, path="secure.db"):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.key = None
        self._fails, self._locked_until = 0, 0.0
        self.conn.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB)")
        cols = ", ".join(f"{f} BLOB" for f in FIELDS)
        self.conn.execute(f"CREATE TABLE IF NOT EXISTS records("
                          f"id INTEGER PRIMARY KEY AUTOINCREMENT, {cols}, "
                          f"created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        self.conn.commit()

    # ---------- authentication ----------
    def is_initialized(self):
        return self.conn.execute("SELECT 1 FROM meta WHERE k='salt'").fetchone() is not None

    def setup(self, password: str):
        """First run: create salt and an encrypted verifier used to check passwords."""
        if self.is_initialized():
            raise AuthError("Database already initialised")
        if len(password) < 8:
            raise AuthError("Password must be at least 8 characters")
        salt = get_random_bytes(16)
        key = derive_key(password, salt)
        self.conn.execute("INSERT INTO meta VALUES('salt', ?)", (salt,))
        self.conn.execute("INSERT INTO meta VALUES('verifier', ?)",
                          (encrypt(key, "OK", b"verifier"),))
        self.conn.commit()
        self.key = key

    def login(self, password: str):
        if time.time() < self._locked_until:
            raise AuthError("Too many failed attempts. Try again later.")
        salt = self.conn.execute("SELECT v FROM meta WHERE k='salt'").fetchone()[0]
        ver = self.conn.execute("SELECT v FROM meta WHERE k='verifier'").fetchone()[0]
        key = derive_key(password, salt)
        try:
            decrypt(key, ver, b"verifier")
        except IntegrityError:
            self._fails += 1
            if self._fails >= MAX_ATTEMPTS:
                self._locked_until, self._fails = time.time() + LOCKOUT_SECONDS, 0
            raise AuthError("Authentication failed")
        self._fails, self.key = 0, key

    def logout(self):
        self.key = None

    def _need_auth(self):
        if self.key is None:
            raise AuthError("Not authenticated")

    # ---------- CRUD ----------
    def _enc_row(self, rec):
        return [encrypt(self.key, str(rec.get(f, "")), f.encode()) for f in FIELDS]

    def _dec_row(self, row):
        return {"id": row[0], **{f: decrypt(self.key, row[i + 1], f.encode())
                                 for i, f in enumerate(FIELDS)}, "created_at": row[-1]}

    def insert(self, rec, commit=True):
        self._need_auth()
        q = f"INSERT INTO records({','.join(FIELDS)}) VALUES({','.join('?' * len(FIELDS))})"
        cur = self.conn.execute(q, self._enc_row(rec))
        if commit:
            self.conn.commit()
        return cur.lastrowid

    def insert_many(self, recs):
        self._need_auth()
        q = f"INSERT INTO records({','.join(FIELDS)}) VALUES({','.join('?' * len(FIELDS))})"
        self.conn.executemany(q, [self._enc_row(r) for r in recs])
        self.conn.commit()

    def get(self, rid):
        self._need_auth()
        row = self.conn.execute("SELECT * FROM records WHERE id=?", (rid,)).fetchone()
        return self._dec_row(row) if row else None

    def list_all(self):
        self._need_auth()
        return [self._dec_row(r) for r in self.conn.execute("SELECT * FROM records")]

    def search(self, term):
        """Encrypted columns can't be queried by SQL, so search after decryption."""
        t = term.lower()
        return [r for r in self.list_all()
                if any(t in str(v).lower() for k, v in r.items() if k in FIELDS)]

    def update(self, rid, rec):
        self._need_auth()
        sets = ",".join(f"{f}=?" for f in FIELDS)
        cur = self.conn.execute(f"UPDATE records SET {sets} WHERE id=?",
                                self._enc_row(rec) + [rid])
        self.conn.commit()
        return cur.rowcount > 0

    def delete(self, rid):
        self._need_auth()
        cur = self.conn.execute("DELETE FROM records WHERE id=?", (rid,))
        self.conn.commit()
        return cur.rowcount > 0

    def close(self):
        self.conn.close()
