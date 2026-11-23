"""Security verification: confidentiality, authentication, integrity, injection."""
import os, shutil, sqlite3, tempfile
from secure_db import SecureDB, AuthError, IntegrityError, decrypt, derive_key

SECRETS = {"full_name": "Alice Wonderland", "email": "alice@secret-mail.com",
           "phone": "555-0199-777", "card_number": "4111111111111111",
           "notes": "TOP-SECRET-NOTE-XYZ"}
results = []


def check(name, cond):
    results.append(cond); print(f"[{'PASS' if cond else 'FAIL'}] {name}")


def raises(exc, fn):
    try: fn()
    except exc: return True
    except Exception: return False
    return False


tmp = tempfile.mkdtemp(); path = os.path.join(tmp, "t.db")
db = SecureDB(path); db.setup("Correct-Horse-Battery"); rid = db.insert(SECRETS); db.close()

# 1. Plaintext disclosure: scan raw file bytes
raw = open(path, "rb").read()
check("No plaintext secrets in raw database file", not any(v.encode() in raw for v in SECRETS.values()))

# 2. Unauthorised access without logging in
db = SecureDB(path)
check("Read blocked before authentication", raises(AuthError, lambda: db.get(rid)))
check("Write blocked before authentication", raises(AuthError, lambda: db.insert(SECRETS)))

# 3. Wrong password
check("Wrong password rejected", raises(AuthError, lambda: db.login("wrong-password")))
db.login("Correct-Horse-Battery")
check("Correct password decrypts original data", db.get(rid)["card_number"] == SECRETS["card_number"])

# 4. Direct SQLite access + wrong key
c = sqlite3.connect(path)
blob = c.execute("SELECT card_number FROM records WHERE id=?", (rid,)).fetchone()[0]
check("Stored value is binary ciphertext, not text", isinstance(blob, bytes) and b"4111" not in blob)
check("Decryption with wrong key fails", raises(IntegrityError, lambda: decrypt(b"\x00" * 32, blob, b"card_number")))

# 5. Randomised encryption
db.insert(SECRETS)
a, b = [r[0] for r in c.execute("SELECT email FROM records")][:2]
check("Same plaintext -> different ciphertext (random nonce)", a != b)

# 6. Tampering / integrity
tampered = bytearray(blob); tampered[-1] ^= 1
c.execute("UPDATE records SET card_number=? WHERE id=?", (bytes(tampered), rid)); c.commit()
check("Tampered ciphertext detected (GCM tag)", raises(IntegrityError, lambda: db.get(rid)))

# 7. Ciphertext swapping between columns
rid2 = db.insert(SECRETS)
email_blob = c.execute("SELECT email FROM records WHERE id=?", (rid2,)).fetchone()[0]
c.execute("UPDATE records SET full_name=? WHERE id=?", (email_blob, rid2)); c.commit()
check("Column-swap attack detected (AAD binding)", raises(IntegrityError, lambda: db.get(rid2)))

# 8. SQL injection
evil = dict(SECRETS, full_name="'; DROP TABLE records;--")
eid = db.insert(evil)
check("SQL injection payload stored harmlessly", db.get(eid)["full_name"] == evil["full_name"])
check("Table survived injection attempt", c.execute("SELECT COUNT(*) FROM records").fetchone()[0] > 0)

# 9. Brute-force lockout
db2 = SecureDB(path)
for _ in range(5): raises(AuthError, lambda: db2.login("guess"))
check("Lockout after 5 failed attempts", raises(AuthError, lambda: db2.login("Correct-Horse-Battery")))

c.close(); db.close(); db2.close(); shutil.rmtree(tmp)
print(f"\n{sum(results)}/{len(results)} tests passed")
