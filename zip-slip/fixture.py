#!/usr/bin/env python3
"""Synthetic archive-upload fixture 1.0.0. Binds IPv4 loopback only.

The server extracts uploaded zip and tar archives into <root>/uploads. It writes only
below --root, and it refuses a root whose folder name does not start with "zipslip-".
"""
import argparse
import io
import json
import os
import tarfile
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

VERSION = "1.0.0"
MAX_BODY = 65536


class Refused(Exception):
    pass


def inside(dest, path):
    real_dest = os.path.realpath(dest)
    return os.path.commonpath([real_dest, os.path.realpath(path)]) == real_dest


def target_for(mode, dest, name):
    if mode == "vulnerable":
        return os.path.join(dest, name)
    target = os.path.join(dest, name)
    if not inside(dest, target):
        raise Refused(name)
    return target


def link_ok(mode, dest, target, linkname):
    if mode == "fixed" and not inside(dest, os.path.join(os.path.dirname(target), linkname)):
        raise Refused(target[len(dest):].lstrip("/") + " -> " + linkname)


def members_of(kind, data):
    """Yield (type, name, payload, linkname) for each archive member."""
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                yield ("dir" if info.is_dir() else "file", info.filename,
                       b"" if info.is_dir() else zf.read(info), None)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for m in tf.getmembers():
                if m.isdir():
                    yield ("dir", m.name, b"", None)
                elif m.issym():
                    yield ("link", m.name, b"", m.linkname)
                elif m.isreg():
                    yield ("file", m.name, tf.extractfile(m).read(), None)


def extract(mode, kind, data, dest):
    members = list(members_of(kind, data))
    if mode == "fixed":  # dry run: refuse the whole archive before writing anything
        for mtype, name, _payload, linkname in members:
            target = target_for(mode, dest, name)
            if mtype == "link":
                link_ok(mode, dest, target, linkname)
    done = []
    for mtype, name, payload, linkname in members:
        target = target_for(mode, dest, name)
        if mtype == "dir":
            os.makedirs(target, exist_ok=True)
        elif mtype == "link":
            link_ok(mode, dest, target, linkname)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            os.symlink(linkname, target)
        else:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(payload)
        done.append(name)
    return done


class Handler(BaseHTTPRequestHandler):
    server_version = "ArchiveFixture/" + VERSION
    sys_version = ""

    def do_POST(self):
        kind = {"/upload/zip": "zip", "/upload/tar": "tar"}.get(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if kind is None:
            return self.reply(404, {"error": "not_found"})
        if length > MAX_BODY:
            return self.reply(413, {"error": "too_large"})
        data = self.rfile.read(length)
        dest = os.path.join(self.server.root, "uploads")
        try:
            done = extract(self.server.mode, kind, data, dest)
        except Refused as exc:
            return self.reply(400, {"error": "member_outside_destination", "member": str(exc)})
        except (zipfile.BadZipFile, tarfile.TarError):
            return self.reply(400, {"error": "bad_archive"})
        self.reply(200, {"extracted": done, "status": "ok"})

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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--root", required=True, help="existing folder named zipslip-*; the server writes only inside it")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    root = os.path.realpath(args.root)
    if not os.path.isdir(root) or not os.path.basename(root).startswith("zipslip-"):
        parser.error("--root must be an existing folder whose name starts with zipslip-")
    os.makedirs(os.path.join(root, "uploads"), exist_ok=True)
    os.makedirs(os.path.join(root, "outside"), exist_ok=True)
    httpd = HTTPServer(("127.0.0.1", args.port), Handler)
    httpd.mode = args.mode
    httpd.root = root
    print(json.dumps({"fixture_version": VERSION, "mode": args.mode, "root": root,
                      "base_url": "http://127.0.0.1:%d" % httpd.server_address[1]}), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
