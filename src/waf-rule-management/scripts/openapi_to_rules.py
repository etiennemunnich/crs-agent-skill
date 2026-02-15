#!/usr/bin/env python3
"""
Generate positive-security ModSecurity v3 rules from OpenAPI 3.x specification.
Rules validate requests BEFORE CRS evaluation. Include generated file before CRS.

Categories generated (in order):
  1. Allowed paths + methods
  2. Required query parameters
  3. Parameter type/enum validation
  4. Content-Type enforcement (for requestBody endpoints)
  5. Auth header presence (from securitySchemes)

All rules use chained conditions (path → check) and consistent tagging.
See references/openapi-to-waf.md for full steering guidance.
"""
import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate ModSec v3 positive-security rules from OpenAPI 3.x spec."
    )
    parser.add_argument(
        "spec",
        type=Path,
        help="OpenAPI spec file (YAML or JSON)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output .conf file (default: stdout)",
    )
    parser.add_argument(
        "--base-id",
        type=int,
        default=200000,
        help="Base rule ID range (default: 200000)",
    )
    parser.add_argument(
        "--basepath",
        default="",
        help="Path prefix for all routes (e.g. /api/v1)",
    )
    parser.add_argument(
        "--mode",
        choices=["enforce", "detect"],
        default="enforce",
        help="enforce=deny invalid, detect=log only (default: enforce)",
    )
    parser.add_argument(
        "--skip-body",
        action="store_true",
        help="Skip Content-Type / body rules",
    )
    parser.add_argument(
        "--skip-auth",
        action="store_true",
        help="Skip auth header presence rules",
    )
    parser.add_argument(
        "--skip-params",
        action="store_true",
        help="Skip required parameter and type validation rules",
    )
    return parser.parse_args()


def load_spec(path: Path) -> dict:
    """Load OpenAPI spec from YAML or JSON."""
    if not path.exists():
        sys.exit(f"Error: Spec file not found: {path}")

    raw = path.read_text(encoding="utf-8", errors="replace")

    if path.suffix in (".yaml", ".yml"):
        if yaml is None:
            sys.exit("Error: PyYAML required for YAML. Install: python3 -m pip install pyyaml")
        return yaml.safe_load(raw)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        sys.exit(f"Error: Invalid JSON: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def path_to_regex(path: str, basepath: str) -> str:
    """Convert OpenAPI path to ModSec @rx regex."""
    full = (basepath + path).rstrip("/") or "/"
    parts = []
    for segment in full.split("/"):
        if not segment:
            continue
        if segment.startswith("{") and segment.endswith("}"):
            parts.append("[^/]+")
        else:
            parts.append(re.escape(segment))
    return "^" + "/" + "/".join(parts) + "(/)?$"


def _action(mode: str, status_code: int) -> str:
    """Return disruptive action string based on mode."""
    if mode == "enforce":
        return f"deny,status:{status_code}"
    return "pass"


def _resolve_ref(spec: dict, ref: str) -> Any:
    """Resolve a simple $ref pointer (e.g. #/components/schemas/Foo)."""
    if not ref.startswith("#/"):
        return {}
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        if isinstance(node, dict):
            node = node.get(p, {})
        else:
            return {}
    return node


def _get_parameters(path_item: dict, method_op: dict, spec: dict) -> List[dict]:
    """Collect parameters from path-level and operation-level, resolving $ref."""
    params = []
    for p in path_item.get("parameters", []):
        if "$ref" in p:
            p = _resolve_ref(spec, p["$ref"])
        params.append(p)
    for p in method_op.get("parameters", []):
        if "$ref" in p:
            p = _resolve_ref(spec, p["$ref"])
        params.append(p)
    return params


HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def collect_paths(spec: dict, basepath: str) -> List[Tuple[str, str, List[str]]]:
    """Return [(path_regex, raw_path, [methods]), ...]."""
    paths = spec.get("paths", {})
    result = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        methods = [
            m.upper() for m in path_item.keys()
            if m.lower() in HTTP_METHODS
        ]
        if methods:
            result.append((path_to_regex(path, basepath), path, methods))

    return result


# ---------------------------------------------------------------------------
# Rule generators
# ---------------------------------------------------------------------------

class IDAllocator:
    """Simple sequential ID allocator."""
    def __init__(self, base: int):
        self._next = base

    def next(self) -> int:
        rid = self._next
        self._next += 1
        return rid


def generate_path_method_rules(paths: list, ids: IDAllocator, mode: str) -> list[str]:
    """Category 1: path + method validation rules."""
    lines = []
    action = _action(mode, 405)

    for path_regex, raw_path, methods in paths:
        rid = ids.next()
        methods_pattern = "|".join(methods)
        lines.append(f"# Allowed methods for {raw_path}")
        lines.append(f'SecRule REQUEST_URI "@rx {path_regex}" \\')
        lines.append(f'    "id:{rid},\\')
        lines.append(f'    phase:1,\\')
        lines.append(f'    chain,\\')
        lines.append(f'    nolog,\\')
        lines.append(f'    pass"')
        lines.append(f'    SecRule REQUEST_METHOD "!@rx ^({methods_pattern})$" \\')
        lines.append(f'        "{action},\\')
        lines.append(f"        log,\\")
        lines.append(f"        msg:'Method not allowed for {raw_path}',\\")
        lines.append(f"        logdata:'%{{MATCHED_VAR}}',\\")
        lines.append(f"        tag:'openapi/method-violation',\\")
        lines.append(f"        tag:'positive-security',\\")
        lines.append(f"        severity:'WARNING'\"")
        lines.append("")

    return lines


def generate_required_param_rules(spec: dict, basepath: str, ids: IDAllocator, mode: str) -> list[str]:
    """Category 2: required query parameter presence rules."""
    lines = []
    action = _action(mode, 400)
    paths_obj = spec.get("paths", {})

    for path, path_item in paths_obj.items():
        if not isinstance(path_item, dict):
            continue
        for method_key in path_item:
            if method_key.lower() not in HTTP_METHODS:
                continue
            method_op = path_item[method_key]
            if not isinstance(method_op, dict):
                continue
            params = _get_parameters(path_item, method_op, spec)
            for param in params:
                if not isinstance(param, dict):
                    continue
                if param.get("in") != "query":
                    continue
                if not param.get("required", False):
                    continue
                name = param.get("name", "")
                if not name:
                    continue
                path_re = path_to_regex(path, basepath)
                rid = ids.next()
                lines.append(f"# Required param '{name}' on {method_key.upper()} {path}")
                lines.append(f'SecRule REQUEST_URI "@rx {path_re}" \\')
                lines.append(f'    "id:{rid},\\')
                lines.append(f'    phase:1,\\')
                lines.append(f'    chain,\\')
                lines.append(f'    nolog,\\')
                lines.append(f'    pass"')
                lines.append(f'    SecRule &ARGS:{name} "@eq 0" \\')
                lines.append(f'        "{action},\\')
                lines.append(f"        log,\\")
                lines.append(f"        msg:'Missing required parameter: {name}',\\")
                lines.append(f"        tag:'openapi/missing-param',\\")
                lines.append(f"        tag:'positive-security',\\")
                lines.append(f"        severity:'WARNING'\"")
                lines.append("")

    return lines


def _type_regex(schema: dict) -> Optional[str]:
    """Return a validation regex for an OpenAPI schema type, or None."""
    if schema.get("enum"):
        escaped = [re.escape(str(v)) for v in schema["enum"]]
        return "^(" + "|".join(escaped) + ")$"

    if schema.get("pattern"):
        return schema["pattern"]

    stype = schema.get("type", "")
    sfmt = schema.get("format", "")

    if stype == "integer":
        return "^-?[0-9]+$"
    if stype == "number":
        return r"^-?[0-9]+(\.[0-9]+)?$"
    if sfmt == "uuid":
        return "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    if sfmt == "date":
        return "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
    if sfmt == "date-time":
        return r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    if sfmt == "email":
        return r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return None


def generate_param_type_rules(spec: dict, basepath: str, ids: IDAllocator, mode: str) -> list[str]:
    """Category 3: parameter type / enum / pattern validation rules."""
    lines = []
    action = _action(mode, 400)
    paths_obj = spec.get("paths", {})

    for path, path_item in paths_obj.items():
        if not isinstance(path_item, dict):
            continue
        for method_key in path_item:
            if method_key.lower() not in HTTP_METHODS:
                continue
            method_op = path_item[method_key]
            if not isinstance(method_op, dict):
                continue
            params = _get_parameters(path_item, method_op, spec)
            for param in params:
                if not isinstance(param, dict):
                    continue
                if param.get("in") not in ("query", "path"):
                    continue
                name = param.get("name", "")
                schema = param.get("schema", {})
                if "$ref" in schema:
                    schema = _resolve_ref(spec, schema["$ref"])
                if not name or not schema:
                    continue
                regex = _type_regex(schema)
                if not regex:
                    continue
                path_re = path_to_regex(path, basepath)
                rid = ids.next()
                is_enum = bool(schema.get("enum"))
                tag = "openapi/param-enum-violation" if is_enum else "openapi/type-violation"
                desc = f"enum violation for {name}" if is_enum else f"type check for {name}"
                lines.append(f"# Param {desc} on {method_key.upper()} {path}")
                lines.append(f'SecRule REQUEST_URI "@rx {path_re}" \\')
                lines.append(f'    "id:{rid},\\')
                lines.append(f'    phase:1,\\')
                lines.append(f'    chain,\\')
                lines.append(f'    nolog,\\')
                lines.append(f'    pass"')
                lines.append(f'    SecRule ARGS:{name} "!@rx {regex}" \\')
                lines.append(f'        "{action},\\')
                lines.append(f"        log,\\")
                lines.append(f"        msg:'Invalid value for parameter {name}',\\")
                lines.append(f"        logdata:'%{{MATCHED_VAR}}',\\")
                lines.append(f"        tag:'{tag}',\\")
                lines.append(f"        tag:'positive-security',\\")
                lines.append(f"        severity:'WARNING'\"")
                lines.append("")

    return lines


def generate_content_type_rules(spec: dict, basepath: str, ids: IDAllocator, mode: str) -> list[str]:
    """Category 4: Content-Type enforcement for requestBody endpoints."""
    lines = []
    paths_obj = spec.get("paths", {})

    for path, path_item in paths_obj.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("post", "put", "patch"):
            op = path_item.get(method)
            if not op or not isinstance(op, dict):
                continue
            req_body = op.get("requestBody")
            if isinstance(req_body, dict) and "$ref" in req_body:
                req_body = _resolve_ref(spec, req_body["$ref"])
            if not req_body or not isinstance(req_body, dict):
                continue
            content = req_body.get("content", {})
            if not content:
                continue
            types = list(content.keys())
            if not types:
                continue
            path_re = path_to_regex(path, basepath)
            # Match start of Content-Type to allow charset suffixes
            pattern = "|".join(re.escape(t) for t in types)
            rid = ids.next()
            action = _action(mode, 415)
            lines.append(f"# Content-Type for {method.upper()} {path}")
            lines.append(f'SecRule REQUEST_URI "@rx {path_re}" \\')
            lines.append(f'    "id:{rid},\\')
            lines.append(f'    phase:1,\\')
            lines.append(f'    chain,\\')
            lines.append(f'    nolog,\\')
            lines.append(f'    pass"')
            lines.append(f'    SecRule REQUEST_METHOD "@streq {method.upper()}" \\')
            lines.append(f'        "chain"')
            lines.append(f'        SecRule REQUEST_HEADERS:Content-Type "!@rx ^({pattern})" \\')
            lines.append(f'            "{action},\\')
            lines.append(f"            log,\\")
            lines.append(f"            msg:'Unsupported Content-Type for {method.upper()} {path}',\\")
            lines.append(f"            logdata:'%{{MATCHED_VAR}}',\\")
            lines.append(f"            tag:'openapi/content-type-violation',\\")
            lines.append(f"            tag:'positive-security',\\")
            lines.append(f"            severity:'WARNING'\"")
            lines.append("")

    return lines


def generate_auth_rules(spec: dict, basepath: str, ids: IDAllocator, mode: str) -> list[str]:
    """Category 5: auth header / API key presence rules from securitySchemes."""
    lines = []
    action = _action(mode, 401)

    # Resolve global security schemes
    components = spec.get("components", {})
    schemes = components.get("securitySchemes", {})
    if not schemes:
        return lines

    # Determine global security requirements
    global_security = spec.get("security", [])

    paths_obj = spec.get("paths", {})

    for path, path_item in paths_obj.items():
        if not isinstance(path_item, dict):
            continue
        for method_key in path_item:
            if method_key.lower() not in HTTP_METHODS:
                continue
            method_op = path_item[method_key]
            if not isinstance(method_op, dict):
                continue

            # Per-operation security overrides global
            op_security = method_op.get("security", global_security)
            if not op_security:
                continue

            # Collect required scheme names from this operation
            required_schemes: Set[str] = set()
            for sec_req in op_security:
                if isinstance(sec_req, dict):
                    required_schemes.update(sec_req.keys())

            for scheme_name in required_schemes:
                scheme = schemes.get(scheme_name, {})
                if not isinstance(scheme, dict):
                    continue

                stype = scheme.get("type", "")
                path_re = path_to_regex(path, basepath)
                rid = ids.next()

                if stype == "apiKey":
                    loc = scheme.get("in", "header")
                    key_name = scheme.get("name", "X-API-Key")
                    if loc == "header":
                        var = f"REQUEST_HEADERS:{key_name}"
                    elif loc == "query":
                        var = f"ARGS:{key_name}"
                    elif loc == "cookie":
                        var = f"REQUEST_COOKIES:{key_name}"
                    else:
                        continue
                    lines.append(f"# Auth: require {key_name} ({loc}) on {method_key.upper()} {path}")
                    lines.append(f'SecRule REQUEST_URI "@rx {path_re}" \\')
                    lines.append(f'    "id:{rid},\\')
                    lines.append(f'    phase:1,\\')
                    lines.append(f'    chain,\\')
                    lines.append(f'    nolog,\\')
                    lines.append(f'    pass"')
                    lines.append(f'    SecRule &{var} "@eq 0" \\')
                    lines.append(f'        "{action},\\')
                    lines.append(f"        log,\\")
                    lines.append(f"        msg:'Missing {key_name} ({loc}) for {method_key.upper()} {path}',\\")
                    lines.append(f"        tag:'openapi/auth-missing',\\")
                    lines.append(f"        tag:'positive-security',\\")
                    lines.append(f"        severity:'CRITICAL'\"")
                    lines.append("")

                elif stype == "http":
                    http_scheme = scheme.get("scheme", "bearer").lower()
                    prefix = "Bearer" if http_scheme == "bearer" else "Basic"
                    lines.append(f"# Auth: require Authorization: {prefix} on {method_key.upper()} {path}")
                    lines.append(f'SecRule REQUEST_URI "@rx {path_re}" \\')
                    lines.append(f'    "id:{rid},\\')
                    lines.append(f'    phase:1,\\')
                    lines.append(f'    chain,\\')
                    lines.append(f'    nolog,\\')
                    lines.append(f'    pass"')
                    lines.append(f'    SecRule &REQUEST_HEADERS:Authorization "@eq 0" \\')
                    lines.append(f'        "{action},\\')
                    lines.append(f"        log,\\")
                    lines.append(f"        msg:'Missing Authorization header for {method_key.upper()} {path}',\\")
                    lines.append(f"        tag:'openapi/auth-missing',\\")
                    lines.append(f"        tag:'positive-security',\\")
                    lines.append(f"        severity:'CRITICAL'\"")
                    lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_rules(spec: dict, args) -> str:
    """Generate full rule file content."""
    basepath = args.basepath.rstrip("/")
    if basepath and not basepath.startswith("/"):
        basepath = "/" + basepath

    paths = collect_paths(spec, basepath)
    if not paths:
        return "# No paths found in OpenAPI spec\n"

    ids = IDAllocator(args.base_id)

    lines = [
        "# Positive-security rules generated from OpenAPI spec",
        f"# Include this file BEFORE CRS rules",
        f"# Base ID: {args.base_id}, Mode: {args.mode}",
        "# Tag: positive-security (all rules)",
        "# See: references/openapi-to-waf.md",
        "",
    ]

    # Category 1: paths + methods
    lines.append("# === Category 1: Allowed Paths and Methods ===")
    lines.append("")
    lines.extend(generate_path_method_rules(paths, ids, args.mode))

    # Category 2: required parameters
    if not args.skip_params:
        param_rules = generate_required_param_rules(spec, basepath, ids, args.mode)
        if param_rules:
            lines.append("# === Category 2: Required Query Parameters ===")
            lines.append("")
            lines.extend(param_rules)

    # Category 3: parameter type / enum validation
    if not args.skip_params:
        type_rules = generate_param_type_rules(spec, basepath, ids, args.mode)
        if type_rules:
            lines.append("# === Category 3: Parameter Type and Enum Validation ===")
            lines.append("")
            lines.extend(type_rules)

    # Category 4: Content-Type
    if not args.skip_body:
        ct_rules = generate_content_type_rules(spec, basepath, ids, args.mode)
        if ct_rules:
            lines.append("# === Category 4: Content-Type Enforcement ===")
            lines.append("")
            lines.extend(ct_rules)

    # Category 5: Auth headers
    if not args.skip_auth:
        auth_rules = generate_auth_rules(spec, basepath, ids, args.mode)
        if auth_rules:
            lines.append("# === Category 5: Auth Header Presence ===")
            lines.append("# NOTE: Review these rules — auth requirements may differ")
            lines.append("# from the spec in your actual deployment (gateway, CDN, mTLS).")
            lines.append("")
            lines.extend(auth_rules)

    return "\n".join(lines)


def main():
    args = parse_args()
    spec = load_spec(args.spec)

    if "openapi" not in spec and "swagger" not in spec:
        sys.exit("Error: Not a valid OpenAPI/Swagger spec (missing openapi/swagger field)")

    output = generate_rules(spec, args)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
