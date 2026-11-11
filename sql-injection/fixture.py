#!/usr/bin/env python3
"""Synthetic SQL injection fixture 1.0.0. In-memory sqlite3, binds IPv4 loopback only.

Modes:
  vulnerable  every query is built by string concatenation
  bound       values use ? placeholders; the ORDER BY column is still concatenated
  fixed       values use ? placeholders; the ORDER BY column comes from an allowlist
"""
import argparse
import hashlib
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

VERSION = "1.0.0"
SORT_COLUMNS = {"name": "name", "price": "price"}


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_db():
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw_hash TEXT);"
        "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);"
        "CREATE TABLE orders (id INTEGER PRIMARY KEY, owner TEXT, item TEXT);"
    )
    db.executemany("INSERT INTO users (username, pw_hash) VALUES (?, ?)", [
        ("alice", sha("demo-alice-pw")), ("bob", sha("demo-bob-pw")), ("o'brien", sha("demo-obrien-pw"))])
    db.executemany("INSERT INTO products (name, price) VALUES (?, ?)", [
        ("Widget small", 4.5), ("Widget large", 9.0), ("Gadget", 7.25), ("Cable", 2.0)])
    db.executemany("INSERT INTO orders (owner, item) VALUES (?, ?)", [
        ("alice", "synthetic order A-1"), ("bob", "synthetic order B-1"), ("carol", "synthetic order C-1")])
    db.commit()
    return db


class Handler(BaseHTTPRequestHandler):
    server_version = "SqliFixture/" + VERSION
    sys_version = ""

    def do_GET(self):
        url = urlsplit(self.path)
        args = {k: v[0] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
        try:
            if url.path == "/search":
                return self.search(args.get("q", ""), args.get("sort", "name"))
            if url.path == "/history":
                return self.history(args.get("id", ""))
        except sqlite3.Error:
            return self.reply(500, {"error": "database_error"})
        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
            if self.path == "/login":
                return self.login(str(data.get("username", "")), str(data.get("password", "")))
            if self.path == "/register":
                return self.register(str(data.get("username", "")))
        except sqlite3.Error:
            return self.reply(500, {"error": "database_error"})
        except ValueError:
            return self.reply(400, {"error": "bad_json"})
        self.reply(404, {"error": "not_found"})

    def login(self, username, password):
        db, mode = self.server.db, self.server.mode
        pw_hash = sha(password)
        if mode == "vulnerable":
            sql = "SELECT username FROM users WHERE username = '" + username + "' AND pw_hash = '" + pw_hash + "'"
            row = db.execute(sql).fetchone()
        else:
            row = db.execute("SELECT username FROM users WHERE username = ? AND pw_hash = ?",
                             (username, pw_hash)).fetchone()
        if row is None:
            return self.reply(401, {"error": "invalid_credentials"})
        self.reply(200, {"ok": True, "user": row[0]})

    def search(self, q, sort):
        db, mode = self.server.db, self.server.mode
        if mode == "vulnerable":
            sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%' ORDER BY " + sort
            rows = db.execute(sql).fetchall()
        else:
            if mode == "fixed":
                if sort not in SORT_COLUMNS:
                    return self.reply(400, {"error": "invalid_sort"})
                sort = SORT_COLUMNS[sort]
            sql = "SELECT id, name, price FROM products WHERE name LIKE ? ORDER BY " + sort
            rows = db.execute(sql, ("%" + q + "%",)).fetchall()
        self.reply(200, {"results": [{"id": r[0], "name": r[1], "price": r[2]} for r in rows]})

    def register(self, username):
        db = self.server.db
        try:
            cur = db.execute("INSERT INTO users (username, pw_hash) VALUES (?, ?)", (username, sha("unused")))
        except sqlite3.IntegrityError:
            return self.reply(409, {"error": "username_taken"})
        db.commit()
        self.reply(201, {"id": cur.lastrowid, "username": username})

    def history(self, user_id):
        db, mode = self.server.db, self.server.mode
        row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return self.reply(404, {"error": "no_such_user"})
        username = row[0]  # stored earlier, so it looks trusted
        if mode == "vulnerable":
            rows = db.execute("SELECT item FROM orders WHERE owner = '" + username + "'").fetchall()
        else:
            rows = db.execute("SELECT item FROM orders WHERE owner = ?", (username,)).fetchall()
        self.reply(200, {"user": username, "orders": [r[0] for r in rows]})

    def reply(self, status, payload):
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("vulnerable", "bound", "fixed"), required=True)
    parser.add_argument("--port", type=int, default=8765, help="0 chooses a free local port")
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)
    server.mode = args.mode
    server.db = make_db()
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode,
                      "base_url": "http://127.0.0.1:" + str(server.server_port)}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
