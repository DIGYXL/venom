import sys
import json
import os
from datetime import datetime
import ast
import random
import string
import io
import tokenize


def _inject_helper(code: str, xor_key: bytes) -> str:
    helper = (
        "\n"
        "def _S(__b64_str):\n"
        "    import base64 as __b64\n"
        "    __raw = __b64.b64decode(__b64_str)\n"
        f"    __k = {repr(xor_key)}\n"
        "    __out = bytearray(len(__raw))\n"
        "    for __i, __b in enumerate(__raw):\n"
        "        __out[__i] = __b ^ __k[__i % len(__k)]\n"
        "    return bytes(__out).decode('utf-8')\n"
    )
    if "def _S(" in code:
        return code
    # Find last import line to inject after
    lines = code.splitlines(True)
    insert_at = 0
    # Skip shebang and encoding header for scanning
    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    if idx < len(lines) and lines[idx].lstrip().startswith("# -*- coding"):
        idx += 1
    last_import = -1
    for i in range(idx, len(lines)):
        stripped = lines[i].lstrip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            last_import = i
        # Stop at first non-empty, non-comment, non-import top-level code
        if stripped and not stripped.startswith(("#", "import ", "from ")):
            break
    insert_at = (last_import + 1) if last_import >= 0 else idx
    return "".join(lines[:insert_at] + [helper] + lines[insert_at:])


def _string_prefix(tokval: str) -> str:
    s = tokval.strip()
    i = 0
    while i < len(s) and s[i] in 'fFbBrRuU':
        i += 1
    return s[:i]


def _is_bytes(prefix: str) -> bool:
    return 'b' in prefix.lower()


def _is_fstring(prefix: str) -> bool:
    return 'f' in prefix.lower()


def _is_raw(prefix: str) -> bool:
    return 'r' in prefix.lower()


def _find_quotes(s: str, i: int):
    quote = s[i]
    if i + 2 < len(s) and s[i:i+3] == quote * 3:
        return quote * 3, i + 3
    return quote, i + 1


def _extract_string_content(tokval: str):
    s = tokval.strip()
    i = len(_string_prefix(s))
    if i >= len(s):
        return None, None, None
    if s[i] not in "'\"":
        return None, None, None
    delim, j = _find_quotes(s, i)
    # Find closing delim
    k = s.rfind(delim)
    if k <= j:
        return None, None, None
    return s[j:k], delim, s


def _xor_then_b64(text: str, key: bytes) -> str:
    data = text.encode('utf-8')
    if not key:
        import base64 as _b64
        return _b64.b64encode(data).decode('utf-8')
    xored = bytearray(len(data))
    for i, b in enumerate(data):
        xored[i] = b ^ key[i % len(key)]
    import base64 as _b64
    return _b64.b64encode(bytes(xored)).decode('utf-8')


def _rewrite_simple_fstring(tokval: str, xor_key: bytes):
    # Only handle non-raw f-strings without bytes
    prefix = _string_prefix(tokval)
    if not _is_fstring(prefix) or _is_bytes(prefix) or _is_raw(prefix):
        return None
    content, delim, full = _extract_string_content(tokval)
    if content is None:
        return None
    parts = []  # list of expr strings: _S('b64') or str(expr)
    buf = []
    i = 0
    depth = 0
    while i < len(content):
        ch = content[i]
        if ch == '{':
            if i + 1 < len(content) and content[i+1] == '{':
                buf.append('{')
                i += 2
                continue
            # flush literal buffer
            if buf:
                literal = ''.join(buf)
                try:
                    # Use json to quote then literal_eval to get actual string value
                    val = ast.literal_eval(json.dumps(literal))
                except Exception:
                    val = literal
                b64 = _xor_then_b64(val, xor_key)
                parts.append("_S('" + b64 + "')")
                buf = []
            # parse expression until matching '}'
            i += 1
            expr_start = i
            depth = 1
            has_format = False
            while i < len(content) and depth > 0:
                if content[i] == '{':
                    depth += 1
                elif content[i] == '}':
                    depth -= 1
                    if depth == 0:
                        break
                elif content[i] == ':' and depth == 1:
                    has_format = True
                i += 1
            expr = content[expr_start:i].strip()
            if not expr or has_format or '!' in expr:
                # give up on complex f-strings
                return None
            parts.append(f"str({expr})")
            i += 1
            continue
        elif ch == '}':
            if i + 1 < len(content) and content[i+1] == '}':
                buf.append('}')
                i += 2
                continue
            # unmatched
            return None
        else:
            buf.append(ch)
            i += 1
            continue
    if buf:
        literal = ''.join(buf)
        try:
            val = ast.literal_eval(json.dumps(literal))
        except Exception:
            val = literal
        b64 = _xor_then_b64(val, xor_key)
        parts.append("_S('" + b64 + "')")
    if not parts:
        return None
    return ' + '.join(parts)


def _should_skip_string_token(tokval: str) -> bool:
    prefix = _string_prefix(tokval)
    if _is_bytes(prefix):
        return True
    return False


def obfuscate_string_literals(code: str, xor_key: bytes) -> str:
    out_tokens = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
        for tok in tokens:
            tok_type, tok_val, start, end, line = tok
            if tok_type == tokenize.STRING and not _should_skip_string_token(tok_val):
                prefix = _string_prefix(tok_val)
                if _is_fstring(prefix):
                    new_expr = _rewrite_simple_fstring(tok_val, xor_key)
                    if new_expr:
                        out_tokens.append((tokenize.NAME, new_expr, start, end, line))
                        continue
                    # fall through to keep original if unsupported
                else:
                    try:
                        # Safely evaluate literal to get its value
                        literal_val = ast.literal_eval(tok_val)
                        if isinstance(literal_val, str):
                            b64 = _xor_then_b64(literal_val, xor_key)
                            new_val = "_S('" + b64 + "')"
                            out_tokens.append((tokenize.NAME, new_val, start, end, line))
                            continue
                    except Exception:
                        pass
            out_tokens.append(tok)
        new_code = tokenize.untokenize(out_tokens)
        return new_code
    except Exception:
        # On any failure, return original code
        return code


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 agent_obfuscate.py <agent_script_path>")
        sys.exit(1)
    
    agent_path = sys.argv[1]
    
    # Create directories (relative to this script location)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(script_dir, 'obfuscate')
    config_dir = os.path.join(base_dir, 'config')
    output_dir = os.path.join(base_dir, 'output')
    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    
    # Read agent code
    with open(agent_path, 'r') as f:
        code = f.read()
    
    # Generate a random 4-byte XOR key and obfuscate string literals first so
    # names referenced inside f-strings become real NAME tokens (e.g., str(VAR_X)).
    xor_key = os.urandom(4)
    code = obfuscate_string_literals(code, xor_key)

    # Load pools from config
    config_path = os.path.join(config_dir, 'default.json')
    if not os.path.exists(config_path):
        print(f"Error: pool file not found at {config_path}. Create it first.")
        sys.exit(1)
    with open(config_path, 'r') as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        print("Error: config must be a JSON object with 'functions', 'arrays', 'variables' (optional: 'classes')")
        sys.exit(1)
    pool_functions = list(cfg.get('functions') or [])
    pool_arrays = list(cfg.get('arrays') or [])
    pool_variables = list(cfg.get('variables') or [])
    pool_classes = list(cfg.get('classes') or [])  # optional; falls back to functions
    if not (pool_functions and pool_arrays and pool_variables):
        print("Error: config pools must contain 'functions', 'arrays', and 'variables' with non-empty arrays")
        sys.exit(1)

    # Collect all names to replace by scanning NAME tokens (post string-obfuscation)
    names_to_replace = set()
    tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
    for tok in tokens:
        if tok.type == tokenize.NAME:
            name = tok.string
            if (
                name.startswith('FUNC_') or
                name.startswith('ARRAY_') or
                name.startswith('VAR_') or
                name.startswith('CLASS_')
            ):
                names_to_replace.add(name)

    # Build mapping from pools (random unique selection)
    random.seed()
    mapping = {}
    def choose(pool):
        if not pool:
            # Fallback: generate a unique placeholder name
            alpha = string.ascii_lowercase
            return 'id_' + ''.join(random.choices(alpha, k=10))
        idx = random.randrange(len(pool))
        val = pool.pop(idx)
        return val

    # Ensure deterministic order for replacement safety
    for original in sorted(names_to_replace, key=len, reverse=True):
        if original.startswith('FUNC_'):
            mapping[original] = choose(pool_functions)
        elif original.startswith('ARRAY_'):
            mapping[original] = choose(pool_arrays)
        elif original.startswith('VAR_'):
            mapping[original] = choose(pool_variables)
        else:  # CLASS_
            # Prefer classes pool if available; otherwise fall back to functions pool
            mapping[original] = choose(pool_classes if pool_classes else pool_functions)

    # Token-based replacement to avoid replacing substrings in other contexts
    out_tokens = []
    replacements = 0
    for tok in tokens:
        if tok.type == tokenize.NAME and tok.string in mapping:
            new_name = mapping[tok.string]
            out_tokens.append((tokenize.NAME, new_name, tok.start, tok.end, tok.line))
            replacements += 1
        else:
            out_tokens.append(tok)
    code = tokenize.untokenize(out_tokens)

    # Inject helper at the end (if not already injected)
    code = _inject_helper(code, xor_key)
    
    # Output file with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = os.path.join(output_dir, f'obfuscated_agent_{timestamp}.py')
    with open(output_path, 'w') as f:
        f.write(code)
    
    print(f"Obfuscated agent created at: {output_path}")
    print(f"Mapping size: {len(mapping)}; Replacements applied: {replacements}")

if __name__ == '__main__':
    main()