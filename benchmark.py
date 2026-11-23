"""Performance evaluation: plaintext SQLite vs AES-256-GCM SecureDB."""
import csv, os, random, sqlite3, string, time
from secure_db import SecureDB, FIELDS

SIZES = [100, 1000, 5000, 10000]


def fake(n):
    r = lambda k: "".join(random.choices(string.ascii_letters + string.digits, k=k))
    return [{"full_name": r(12), "email": r(8) + "@mail.com", "phone": r(10),
             "card_number": "".join(random.choices(string.digits, k=16)),
             "notes": r(60)} for _ in range(n)]


def plain_run(path, recs):
    if os.path.exists(path): os.remove(path)
    c = sqlite3.connect(path)
    c.execute(f"CREATE TABLE records(id INTEGER PRIMARY KEY AUTOINCREMENT,"
              f"{','.join(f + ' TEXT' for f in FIELDS)})")
    q = f"INSERT INTO records({','.join(FIELDS)}) VALUES({','.join('?'*len(FIELDS))})"
    t = time.perf_counter(); c.executemany(q, [[r[f] for f in FIELDS] for r in recs]); c.commit()
    ins = time.perf_counter() - t
    t = time.perf_counter(); c.execute("SELECT * FROM records").fetchall()
    rd = time.perf_counter() - t
    t = time.perf_counter()
    for i in random.sample(range(1, len(recs) + 1), min(100, len(recs))):
        c.execute("SELECT * FROM records WHERE id=?", (i,)).fetchone()
    one = (time.perf_counter() - t) / min(100, len(recs))
    c.close()
    return ins, rd, one, os.path.getsize(path)


def secure_run(path, recs):
    if os.path.exists(path): os.remove(path)
    db = SecureDB(path)
    t = time.perf_counter(); db.setup("benchmark-pass"); kdf = time.perf_counter() - t
    t = time.perf_counter(); db.insert_many(recs); ins = time.perf_counter() - t
    t = time.perf_counter(); db.list_all(); rd = time.perf_counter() - t
    t = time.perf_counter()
    for i in random.sample(range(1, len(recs) + 1), min(100, len(recs))):
        db.get(i)
    one = (time.perf_counter() - t) / min(100, len(recs))
    db.close()
    return ins, rd, one, os.path.getsize(path), kdf


if __name__ == "__main__":
    rows = []
    print(f"{'N':>6} | {'ins plain':>9} {'ins AES':>9} | {'read plain':>10} {'read AES':>9} | "
          f"{'size plain':>10} {'size AES':>9} {'overhead':>8} | {'1-rec AES(ms)':>13}")
    for n in SIZES:
        recs = fake(n)
        p = plain_run("bench_plain.db", recs)
        s = secure_run("bench_secure.db", recs)
        ov = (s[3] / p[3] - 1) * 100
        rows.append([n, *p, *s, ov])
        print(f"{n:>6} | {p[0]:>9.4f} {s[0]:>9.4f} | {p[1]:>10.4f} {s[1]:>9.4f} | "
              f"{p[3]:>10} {s[3]:>9} {ov:>7.1f}% | {s[2]*1000:>13.3f}")
    print(f"\nOne-time login cost (scrypt KDF): {rows[-1][-2]*1000:.0f} ms")
    with open("benchmark_results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n", "plain_insert_s", "plain_readall_s", "plain_get1_s", "plain_bytes",
                    "aes_insert_s", "aes_readall_s", "aes_get1_s", "aes_bytes", "kdf_s", "size_overhead_pct"])
        w.writerows(rows)
    for f in ("bench_plain.db", "bench_secure.db"): os.remove(f)
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        ns = [r[0] for r in rows]
        fig, ax = plt.subplots(1, 2, figsize=(10, 4))
        ax[0].plot(ns, [r[1] for r in rows], "o-", label="Plain insert")
        ax[0].plot(ns, [r[5] for r in rows], "o-", label="AES insert")
        ax[0].plot(ns, [r[2] for r in rows], "s--", label="Plain read-all")
        ax[0].plot(ns, [r[6] for r in rows], "s--", label="AES read-all")
        ax[0].set_xlabel("Records"); ax[0].set_ylabel("Seconds"); ax[0].legend(); ax[0].set_title("Execution time")
        ax[1].bar([str(n) for n in ns], [r[-1] for r in rows]); ax[1].set_title("Storage overhead (%)")
        plt.tight_layout(); plt.savefig("benchmark_chart.png", dpi=120)
    except ImportError:
        pass
