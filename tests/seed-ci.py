#!/usr/bin/env python3
"""CI seed for the Atrium test batteries.

Creates the users and channels the batteries expect, mirroring the local
demo seed: jdoe and asmith (password Password!2026) and channels
1 #general, 2 #help-desk, 3 #random with fixed memberships. The server
seeds the admin account itself at first start; run this only after the
server has started once.

Connection is through the psql CLI, configured by the standard libpq
environment variables (PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE);
PSQL overrides the psql binary path. SQL goes through a temp file, never
a shell string: password hashes contain $ segments that shell expansion
would eat.
"""
import base64, hashlib, os, subprocess, sys, tempfile

PSQL = os.environ.get('PSQL', 'psql')


def psql(sql):
    fd, path = tempfile.mkstemp(suffix='.sql')
    with os.fdopen(fd, 'w') as f:
        f.write(sql)
    try:
        r = subprocess.run([PSQL, '-t', '-A', '-v', 'ON_ERROR_STOP=1', '-f', path],
                           capture_output=True, text=True)
    finally:
        os.unlink(path)
    if r.returncode != 0:
        print('PSQL FAIL:', r.stderr.strip())
        sys.exit(1)
    return r.stdout.strip()


def hash_pw(pw):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 210000)
    return f"pbkdf2-sha256$210000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


admin_id = psql("SELECT id FROM users WHERE username = 'admin'")
assert admin_id, 'admin not seeded by the server yet'
h = hash_pw('Password!2026')
psql(f"""INSERT INTO users (username, display_name, email, password_hash)
         VALUES ('jdoe', 'John Doe', 'jdoe@example.local', '{h}')""")
psql(f"""INSERT INTO users (username, display_name, email, password_hash)
         VALUES ('asmith', 'Alice Smith', 'asmith@example.local', '{h}')""")
jdoe_id = psql("SELECT id FROM users WHERE username = 'jdoe'")
asmith_id = psql("SELECT id FROM users WHERE username = 'asmith'")
for cid, name in ((1, 'general'), (2, 'help-desk'), (3, 'random')):
    psql(f"""INSERT INTO channels (id, kind, name, created_by)
             OVERRIDING SYSTEM VALUE VALUES ({cid}, 'channel', '{name}', {admin_id})""")
psql("SELECT setval(pg_get_serial_sequence('channels', 'id'), (SELECT MAX(id) FROM channels))")
psql(f"INSERT INTO channel_members (channel_id, user_id, role) VALUES (1, {admin_id}, 'owner'), (2, {admin_id}, 'member'), (3, {admin_id}, 'member')")
psql(f"INSERT INTO channel_members (channel_id, user_id, role) VALUES (1, {jdoe_id}, 'member'), (2, {jdoe_id}, 'member'), (3, {jdoe_id}, 'owner')")
psql(f"INSERT INTO channel_members (channel_id, user_id, role) VALUES (1, {asmith_id}, 'member')")
print(f'seeded: admin={admin_id} jdoe={jdoe_id} asmith={asmith_id}')
