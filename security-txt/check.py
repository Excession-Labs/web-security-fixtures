#!/usr/bin/env python3
"""Check a security.txt file against the rules of RFC 9116 (Python standard library only).

Usage:
  python3 check.py security.txt                  check a local file
  python3 check.py --site https://example.com    fetch /.well-known/security.txt and check it
  python3 check.py https://example.com/.well-known/security.txt   check one URL

Exit status: 0 when there is no ERROR finding, 1 when there is at least one, 2 on bad usage.
Levels: ERROR breaks a MUST or MUST NOT in RFC 9116. WARN breaks a SHOULD or RECOMMENDED, or
is a risk the RFC names. NOTE is information. OK is a rule that passed.
The tool does not verify an OpenPGP signature and does not check that a contact answers.
"""
import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
SIGNED_START = "-----BEGIN PGP SIGNED MESSAGE-----"
SIG_START = "-----BEGIN PGP SIGNATURE-----"
SIG_END = "-----END PGP SIGNATURE-----"
URI_FIELDS = ("acknowledgments", "canonical", "contact", "encryption", "hiring", "policy")
KNOWN = URI_FIELDS + ("expires", "preferred-languages")
FIELD_RE = re.compile(r"^([\x21-\x39\x3b-\x7e]+):( (.*\S)?)?[ \t]*$")
URI_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):\S+$")
DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+\-]\d{2}:\d{2})$")
LANG_RE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, rule, rfc, message):
        self.items.append({"level": level, "rule": rule, "rfc9116": rfc, "message": message})

    @property
    def errors(self):
        return [i for i in self.items if i["level"] == "ERROR"]


def parse_time(value):
    match = DATE_RE.match(value)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    zone = match.group(8)
    if zone in ("Z", "z"):
        tz = datetime.timezone.utc
    else:
        sign = 1 if zone[0] == "+" else -1
        tz = datetime.timezone(sign * datetime.timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
    try:
        return datetime.datetime(year, month, day, hour, minute, min(second, 59), tzinfo=tz)
    except ValueError:
        return None


def unsign(text, report):
    """Return the cleartext of an OpenPGP clearsigned file, or the text itself when unsigned."""
    lines = text.splitlines()
    if not lines or lines[0].rstrip() != SIGNED_START:
        report.add("NOTE", "signature", "2.3", "File is not signed. A signature is RECOMMENDED, with a Canonical field.")
        return lines
    body, index = [], 1
    while index < len(lines) and lines[index].strip() != "":
        index += 1
    index += 1
    while index < len(lines) and lines[index].rstrip() != SIG_START:
        line = lines[index]
        body.append(line[2:] if line.startswith("- ") else line)
        index += 1
    if index >= len(lines) or SIG_END not in text:
        report.add("ERROR", "signature", "4", "Signed file has no complete PGP SIGNATURE block.")
    else:
        report.add("NOTE", "signature", "2.3", "Signed file has the clearsign structure. This tool does not verify the signature.")
    return body


def check_text(text, source_url=None, now=None):
    report = Report()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if len(text.encode("utf-8")) > 32 * 1024:
        report.add("WARN", "size", "5.4", "File is larger than 32 KB. A researcher may refuse to parse it.")
    lines = unsign(text, report)
    if len(lines) > 1000:
        report.add("WARN", "size", "5.4", "File has more than 1,000 lines. A researcher may refuse to parse it.")
    fields = {}
    for number, line in enumerate(lines, 1):
        if line.strip() == "" or line.startswith("#"):
            continue
        match = FIELD_RE.match(line)
        if not match or match.group(3) is None:
            report.add("ERROR", "syntax", "2, 4", "Line %d is not a comment, a blank line or 'Name: value' (one space after the colon): %r" % (number, line[:60]))
            continue
        if len(line) > 2048:
            report.add("WARN", "size", "5.4", "Line %d is longer than 2,048 characters." % number)
        fields.setdefault(match.group(1).lower(), []).append((number, match.group(3)))

    # Contact: required, may repeat, must be a URI, a web URI must be https.
    contacts = fields.get("contact", [])
    if not contacts:
        report.add("ERROR", "contact-required", "2.5.3", "Contact is missing. It MUST be present at least once.")
    else:
        report.add("OK", "contact-required", "2.5.3", "%d Contact field(s) present." % len(contacts))

    # Expires: required, exactly once, RFC 3339 date-time, not stale.
    expires = fields.get("expires", [])
    if not expires:
        report.add("ERROR", "expires-required", "2.5.5", "Expires is missing. It MUST be present exactly once.")
    else:
        if len(expires) > 1:
            report.add("ERROR", "expires-once", "2.5.5", "Expires appears %d times. It MUST NOT appear more than once." % len(expires))
        stamp = parse_time(expires[0][1])
        if stamp is None:
            report.add("ERROR", "expires-format", "2.5.5", "Expires value %r is not an RFC 3339 date-time (example: 2027-06-30T23:59:59Z)." % expires[0][1])
        elif stamp <= now:
            report.add("ERROR", "expires-stale", "2.5.5, 5.3", "Expires %s is in the past. The data is stale and should not be used." % expires[0][1])
        else:
            report.add("OK", "expires-format", "2.5.5", "Expires %s is a valid date-time in the future." % expires[0][1])
            if stamp - now > datetime.timedelta(days=366):
                report.add("WARN", "expires-horizon", "2.5.5", "Expires is more than a year away. RFC 9116 RECOMMENDS less than a year.")

    # URI-valued fields.
    for name in URI_FIELDS:
        for number, value in fields.get(name, []):
            label = name.capitalize() if name != "acknowledgments" else "Acknowledgments"
            match = URI_RE.match(value)
            if not match:
                hint = " Use mailto: for an email address and tel: for a phone number." if name == "contact" else ""
                report.add("ERROR", "uri", "2.5, 4", "%s on line %d is not a URI: %r.%s" % (label, number, value, hint))
                continue
            scheme = match.group(1).lower()
            if scheme == "http":
                report.add("ERROR", "https-only", "2.5.3, 5.7", "%s on line %d uses http://. A web URI MUST begin with https://." % (label, number))
            elif scheme == "mailto" and "@" not in value:
                report.add("ERROR", "uri", "2.5.3", "Contact on line %d is a mailto: URI with no address." % number)
            elif scheme in ("https", "mailto", "tel", "dns", "openpgp4fpr"):
                report.add("OK", "uri", "2.5", "%s on line %d: %s" % (label, number, value))
            else:
                report.add("NOTE", "uri", "2.5", "%s on line %d uses the %s: scheme. The RFC allows any URI." % (label, number, scheme))

    languages = fields.get("preferred-languages", [])
    if len(languages) > 1:
        report.add("ERROR", "languages-once", "2.5.8", "Preferred-Languages appears %d times. It MUST NOT appear more than once." % len(languages))
    for number, value in languages[:1]:
        tags = [t.strip() for t in value.split(",")]
        if not all(LANG_RE.match(t) for t in tags):
            report.add("ERROR", "languages-format", "2.5.8", "Preferred-Languages on line %d is not a comma-separated list of language tags: %r." % (number, value))

    canonicals = [v for _, v in fields.get("canonical", [])]
    if source_url and canonicals and source_url not in canonicals:
        report.add("WARN", "canonical-mismatch", "2.5.2", "The file was fetched from %s, which no Canonical field lists. The file SHOULD NOT be trusted." % source_url)
    for name in sorted(set(fields) - set(KNOWN)):
        report.add("NOTE", "extension", "2.4", "Field %r is not defined in RFC 9116. Researchers MUST ignore fields they do not support." % name)
    return report


def fetch(url, allow_insecure_local, report):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        if allow_insecure_local and parts.hostname in LOCAL_HOSTS:
            report.add("WARN", "https-transport", "3, 5.7", "Fetched over http on %s. RFC 9116 section 5.7 allows this for localhost only with extra human validation." % parts.hostname)
        else:
            report.add("ERROR", "https-transport", "3, 5.7", "File is served over %s. Access MUST use https." % parts.scheme)
    request = urllib.request.Request(url, headers={"User-Agent": "security-txt-check/" + VERSION})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status, headers, body, final = response.status, response.headers, response.read(65536), response.geturl()
    except urllib.error.HTTPError as exc:
        status, headers, body, final = exc.code, exc.headers, exc.read(65536), url
    except (urllib.error.URLError, OSError) as exc:
        report.add("ERROR", "fetch", "3", "Could not fetch %s: %s" % (url, exc))
        return None
    if final != url:
        report.add("NOTE", "redirect", "3, 5.2", "Redirected to %s. Check where a redirect leads." % final)
    if status != 200:
        report.add("ERROR", "http-status", "3", "GET %s returned HTTP %d, not 200." % (url, status))
        return None
    ctype = headers.get("Content-Type", "")
    media = ctype.split(";")[0].strip().lower()
    charset = re.search(r"charset=([^;\s]+)", ctype, re.I)
    if media != "text/plain":
        report.add("ERROR", "content-type", "3, 4", "Content-Type is %r. It MUST be text/plain." % ctype)
    elif charset and charset.group(1).strip('"').lower() != "utf-8":
        report.add("ERROR", "content-type", "3, 4", "charset is %r. It MUST be utf-8." % charset.group(1))
    else:
        report.add("OK", "content-type", "3, 4", "Content-Type is %r." % ctype)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        report.add("ERROR", "encoding", "4", "Body is not valid UTF-8.")
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", help="local file path or full URL of a security.txt file")
    parser.add_argument("--site", help="site base URL; the tool fetches BASE/.well-known/security.txt")
    parser.add_argument("--allow-insecure-local", action="store_true", help="downgrade http on 127.0.0.1 or localhost from ERROR to WARN (for test servers)")
    parser.add_argument("--now", help="fixed UTC time (RFC 3339) for the Expires comparison")
    parser.add_argument("--json", action="store_true", help="print findings as JSON")
    args = parser.parse_args(argv)
    if bool(args.target) == bool(args.site):
        parser.error("give either a target or --site")
    now = parse_time(args.now) if args.now else None
    if args.now and now is None:
        parser.error("--now must be an RFC 3339 date-time")
    report, text, source = Report(), None, None
    if args.site:
        base = args.site.rstrip("/")
        source = base + "/.well-known/security.txt"
        text = fetch(source, args.allow_insecure_local, report)
        if text is None:
            legacy = base + "/security.txt"
            legacy_report = Report()
            if fetch(legacy, args.allow_insecure_local, legacy_report) is not None:
                report.add("NOTE", "legacy-path", "3", "A file exists at %s. That legacy path is allowed only for compatibility; the /.well-known/ path MUST be used." % legacy)
    elif re.match(r"^https?://", args.target):
        source = args.target
        text = fetch(source, args.allow_insecure_local, report)
    else:
        with open(args.target, "rb") as handle:
            raw = handle.read()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            report.add("ERROR", "encoding", "4", "File is not valid UTF-8.")
    if text is not None:
        report.items.extend(check_text(text, source, now).items)
    if args.json:
        print(json.dumps({"checker_version": VERSION, "source": source or args.target, "errors": len(report.errors), "findings": report.items}, indent=2))
    else:
        for item in report.items:
            print("%-5s %-18s RFC 9116 s%-9s %s" % (item["level"], item["rule"], item["rfc9116"], item["message"]))
        print("RESULT: %s (%d error(s))" % ("FAIL" if report.errors else "PASS", len(report.errors)))
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
