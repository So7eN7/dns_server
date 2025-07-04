import sqlite3

def init_db():
    conn = sqlite3.connect("dns.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_records (
            qname TEXT,
            qtype INTEGER,
            rdata TEXT,
            ttl INTEGER,
            PRIMARY KEY (qname, qtype)
        )
    """)

    cursor.executemany(
        "INSERT OR REPLACE INTO dns_records (qname, qtype, rdata, ttl) VALUES (?, ?, ?, ?)",
        [
            ("example.com", 1, "93.184.216.34", 3600), # A record
            ("example.com", 15, "10 mail.example.com", 3600), # MX record
            ("www.example.com", 5, "example.com", 3600), # CNAME record
        ]
    )

    conn.commit()
    conn.close()
    print("Database dns.db initialized.")

if __name__ == "__main__":
    init_db()
