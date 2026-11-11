#!/usr/bin/env python3
"""Local GraphQL fixture on 127.0.0.1. Needs graphql-core (see README.txt).

Two switches change the behaviour:
  --introspection on|off   off adds graphql-core's NoSchemaIntrospectionCustomRule
  --authz on|off           on makes the adminUserRecord resolver check the caller's role
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

import graphql
from graphql import (GraphQLArgument, GraphQLField, GraphQLID, GraphQLNonNull, GraphQLObjectType,
                     GraphQLSchema, GraphQLString, NoSchemaIntrospectionCustomRule, execute, parse,
                     specified_rules, validate)
from graphql.error import GraphQLError

VERSION = "1.0.0"

# Synthetic data. Tokens are public demo strings with no value outside this fixture.
TOKENS = {"demo-alice-token": "alice", "demo-bob-token": "bob", "demo-admin-token": "admin"}
ROLES = {"alice": "user", "bob": "user", "admin": "admin"}
USERS = {
    "alice": {"id": "alice", "email": "alice@example.invalid", "ssn_last4": "1111"},
    "bob": {"id": "bob", "email": "bob@example.invalid", "ssn_last4": "2222"},
    "admin": {"id": "admin", "email": "admin@example.invalid", "ssn_last4": "9999"},
}

USER = GraphQLObjectType("UserRecord", {
    "id": GraphQLField(GraphQLNonNull(GraphQLID)),
    "email": GraphQLField(GraphQLString),
    "ssn_last4": GraphQLField(GraphQLString),
})


def resolve_me(root, info):
    return USERS[info.context["identity"]]


def resolve_admin_user_record(root, info, id):
    # Vulnerable mode stops here: any authenticated caller gets any record.
    if info.context["authz"] and ROLES[info.context["identity"]] != "admin":
        raise GraphQLError("forbidden", extensions={"code": "FORBIDDEN"})
    return USERS.get(id)


SCHEMA = GraphQLSchema(query=GraphQLObjectType("Query", {
    "me": GraphQLField(USER, resolve=resolve_me),
    # Not used by the public client, but present in the schema.
    "adminUserRecord": GraphQLField(USER, args={"id": GraphQLArgument(GraphQLNonNull(GraphQLID))},
                                    resolve=resolve_admin_user_record),
}))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/graphql":
            return self.reply(404, {"error": "not_found"})
        auth = self.headers.get("Authorization", "")
        identity = TOKENS.get(auth[7:]) if auth.startswith("Bearer ") else None
        if identity is None:
            return self.reply(401, {"error": "authentication_required"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            query = json.loads(self.rfile.read(length))["query"]
            document = parse(query)
        except (ValueError, KeyError, TypeError, GraphQLError) as exc:
            return self.reply(400, {"errors": [{"message": "bad request: " + type(exc).__name__}]})
        rules = list(specified_rules)
        if not self.server.introspection:
            rules.append(NoSchemaIntrospectionCustomRule)
        errors = validate(SCHEMA, document, rules)
        if errors:
            return self.reply(200, {"errors": [e.formatted for e in errors]})
        result = execute(SCHEMA, document, context_value={"identity": identity, "authz": self.server.authz})
        payload = {"data": result.data}
        if result.errors:
            payload["errors"] = [e.formatted for e in result.errors]
        self.reply(200, payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--introspection", choices=("on", "off"), default="on")
    parser.add_argument("--authz", choices=("on", "off"), default="off")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), Handler)  # loopback only
    server.introspection = args.introspection == "on"
    server.authz = args.authz == "on"
    print(json.dumps({"fixture_version": VERSION, "introspection": args.introspection, "authz": args.authz,
                      "graphql_core": graphql.__version__,
                      "base_url": "http://127.0.0.1:%d" % server.server_address[1]}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
