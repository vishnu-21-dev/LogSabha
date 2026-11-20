"""QuickPay's SQLite database. Every row is fake (names are made up, emails end in .invalid)."""
import hashlib
import hmac
import random
import secrets
import sqlite3

FIRST = ["Asha", "Ravi", "Meera", "Kiran", "Divya", "Arjun", "Neha", "Vikram", "Sana", "Rohan",
         "Isha", "Karthik", "Anita", "Manish", "Pooja", "Suresh", "Lata", "Imran", "Tara", "Dev"]
LAST = ["Sharma", "Iyer", "Nair", "Reddy", "Patel", "Singh", "Menon", "Gupta", "Rao", "Das",
        "Khan", "Joshi", "Bose", "Pillai", "Shetty", "Kulkarni", "Mehta", "Chopra", "Verma", "Naidu"]
CITIES = ["Bengaluru", "Pune", "Chennai", "Hyderabad", "Kochi", "Jaipur", "Nagpur", "Indore"]
STAFF = ("analyst", "auditor")


def connect(path):
    con = sqlite3.connect(str(path), timeout=10)
    con.row_factory = sqlite3.Row
    return con


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 20000).hex()


def check_password(password: str, salt_hex: str, expected_hex: str) -> bool:
    return hmac.compare_digest(hash_password(password, bytes.fromhex(salt_hex)), expected_hex)


def init_db(path, demo_password: str, customers: int):
    """Create tables, seed fake customers (the same ones every time) and the staff logins."""
    with connect(path) as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS customers(
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL,
                city TEXT NOT NULL, balance_cents INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS staff(
                username TEXT PRIMARY KEY, salt TEXT NOT NULL, password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(
                token TEXT PRIMARY KEY, username TEXT NOT NULL, created_at REAL NOT NULL);
        """)
        if con.execute("SELECT COUNT(*) FROM customers").fetchone()[0] == 0:
            rnd = random.Random(42)
            for i in range(1, customers + 1):
                first, last = rnd.choice(FIRST), rnd.choice(LAST)
                con.execute("INSERT INTO customers VALUES(?,?,?,?,?)",
                            (i, "%s %s" % (first, last), "%s.%s%d@example.invalid" % (first.lower(), last.lower(), i),
                             rnd.choice(CITIES), rnd.randint(1000, 5_000_000)))
        for user in STAFF:
            salt = secrets.token_bytes(16)
            con.execute("INSERT OR REPLACE INTO staff VALUES(?,?,?)",
                        (user, salt.hex(), hash_password(demo_password, salt)))
