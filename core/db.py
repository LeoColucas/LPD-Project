# core/db.py
import sqlite3
from core.models import Finding

def init_db(db_path: str = "reports/lpd.sqlite") -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS findings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      details TEXT NOT NULL,
      target TEXT,
      source TEXT,
      ip TEXT,
      user TEXT
    )
    """)
    con.commit()
    return con

def insert_findings(con: sqlite3.Connection, items: list[Finding]) -> None:
    cur = con.cursor()
    cur.executemany("""
      INSERT INTO findings(timestamp, category, severity, title, details, target, source, ip, user)
      VALUES(?,?,?,?,?,?,?,?,?)
    """, [
      (f.timestamp.isoformat(), f.category, f.severity, f.title, f.details,
       f.target, f.source, f.ip, f.user)
      for f in items
    ])
    con.commit()

def stats_by_severity(con: sqlite3.Connection) -> list[tuple[str,int]]:
    cur = con.cursor()
    cur.execute("""
      SELECT severity, COUNT(*) FROM findings
      GROUP BY severity
      ORDER BY COUNT(*) DESC
    """)
    return cur.fetchall()
