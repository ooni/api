#!/usr/bin/env python3
"""
Extract error handlers from ooniapi

jer("error code", "error formatter string", a=1, b=2, ...)

Error out if the handlers are different from error_handlers.json
"""

from pathlib import Path
import ast
import json
import sys


def scan(desc, n):
    """Scan for error handlers"""
    for x in ast.walk(n):
        if not isinstance(x, ast.Call):
            continue
        if not hasattr(x.func, "id"):
            continue
        if x.func.id != "jer":
            continue
        error_id = x.args[0].value
        tpl = x.args[1].value
        if error_id == "":
            error_id = tpl.title().replace(" ", "")
        args = [k.arg for k in x.keywords]
        yield [error_id, tpl, args, desc]


def extract_err_handlers(pyf, node, err_handlers):
    # Look for a top-level function
    top_levels = [n for n in node.body if isinstance(n, ast.FunctionDef)]

    for n in top_levels:
        desc = f"{pyf}:{n.name}"
        print("Scanning function", desc)

        # Look for a function call named "jer"
        for eh in scan(desc, n):
            err_handlers.append(eh)


def cleanup(err_handlers) -> list:
    id_lookup = {}
    out = []
    for errid, tpl, args, desc in err_handlers:
        if errid not in id_lookup:
            id_lookup[errid] = tpl
            # Record only one occurrence of jer("Foo", ...)
            out.append([errid, tpl, args, desc])
        else:
            if id_lookup[errid] != tpl:
                # We don't want to have both jer("Foo", "Something") and
                # jer("Foo", "Something else")
                print("Error: inconsistent templates {errid} in {desc}")
                print("{tpl} VS {id_lookup[errid]}")
                sys.exit(1)

    return out


def main() -> None:
    saved_handlers = json.load(Path("error_handlers.json").open())

    py_files = sorted(Path("ooniapi").rglob("*.py"))

    err_handlers = []
    for pyf in py_files:
        node = ast.parse(pyf.read_text())
        extract_err_handlers(pyf, node, err_handlers)

    err_handlers = cleanup(err_handlers)
    if err_handlers != saved_handlers:
        print("Change in error handlers detected!")
        print(json.dumps(err_handlers, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
