#!/usr/bin/env python3
"""PreToolUse guard for the Lovable `query_database` MCP tool.

`mcp__Lovable__query_database` is on the permissions allowlist so that
read-only SQL runs without a permission prompt. This guard reads the SQL
first and, when the statement is not plainly read-only, turns the call back
into a normal permission prompt ("ask"). For read-only SQL it prints nothing,
so the allowlist rule applies.

It is a keyword check, not a security boundary: a SELECT that calls a
database function with side effects still passes.
"""
import json
import re
import sys

READ_START = re.compile(r"^(select|with|explain|show|table|values)\b", re.I)
WRITE_MARKERS = re.compile(
    r"\b(insert|update|delete|merge|into"            # data-modifying CTEs, SELECT INTO
    r"|setval|nextval|set_config|pg_notify"         # writing built-ins
    r"|pg_terminate_backend|pg_cancel_backend|pg_reload_conf"
    r"|lo_import|lo_export|dblink"
    r"|cron\.(schedule|unschedule|alter_job)"       # pg_cron
    r"|net\.http_\w+|vault\.\w+)\b",                # pg_net calls, vault writes
    re.I,
)


def ask(reason):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }))


def main():
    try:
        data = json.load(sys.stdin)
    except Exception:
        return ask("Lovable SQL guard: could not read the tool input")
    sql = (data.get("tool_input") or {}).get("sql")
    if not isinstance(sql, str) or not sql.strip():
        return ask("Lovable SQL guard: no SQL text to check")

    s = re.sub(r"--[^\n]*", " ", sql)                              # line comments
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)                   # block comments
    s = re.sub(r"\$([A-Za-z_]*)\$.*?\$\1\$", "''", s, flags=re.S)  # dollar-quoted text
    s = re.sub(r"'(?:[^']|'')*'", "''", s)                         # string literals
    s = s.strip()
    while s.endswith(";"):
        s = s[:-1].rstrip()

    if ";" in s:
        return ask("Lovable SQL guard: more than one statement")
    if not READ_START.match(s):
        return ask("Lovable SQL guard: not a SELECT / WITH / EXPLAIN / SHOW statement")
    hit = WRITE_MARKERS.search(s)
    if hit:
        return ask("Lovable SQL guard: statement contains '%s'" % hit.group(0))
    # Read-only: no decision printed, the allowlist rule applies.


if __name__ == "__main__":
    main()
