"""Verify actual candidate indexes against SQLite using synthetic users only."""
from pathlib import Path
import re, sqlite3, uuid
source=(Path(__file__).resolve().parents[1] / 'Source.js').read_text(encoding='utf-8')
db=sqlite3.connect(':memory:')
db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, uuid TEXT, trojan_hash TEXT, is_active INTEGER)')
users=[(i, f'user{i}', str(uuid.uuid4()), f'hash{i}', 1) for i in range(112)]
db.executemany('INSERT INTO users VALUES (?,?,?,?,?)',users)
indexes=re.findall(r'"(CREATE INDEX IF NOT EXISTS zeus_users_[^"\n]+)"',source)
assert len(indexes)==5
for sql in indexes: db.execute(sql)
queries=[
 ('SELECT * FROM users WHERE uuid = ? COLLATE NOCASE',(users[50][2].upper(),)),
 ('SELECT * FROM users WHERE uuid = ?',(users[50][2],)),
 ('SELECT * FROM users WHERE username = ? COLLATE NOCASE OR uuid = ?',('USER50','USER50')),
 ('SELECT * FROM users WHERE trojan_hash = ? OR uuid = ? COLLATE NOCASE',('hash50','hash50')),
 ('SELECT * FROM users WHERE substr(uuid, -12) = ? COLLATE NOCASE AND is_active = 1',(users[50][2][-12:].upper(),)),
]
for sql,args in queries:
 assert sql in source
 plan='; '.join(row[3] for row in db.execute('EXPLAIN QUERY PLAN '+sql,args))
 assert 'SCAN users' not in plan,plan
 assert 'SEARCH users USING INDEX' in plan,plan
 assert db.execute(sql,args).fetchone()[0]==50
 print(plan)
print('All 5 hot lookup plans use indexes; 112 synthetic users, identity unchanged.')
