#!/usr/bin/env python3
import re
import ast
import base64
import sys
import os
from functools import reduce
from collections import defaultdict

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

def log(message, level="info"):
    if HAS_COLOR:
        colors = {"debug": Fore.CYAN, "info": Fore.GREEN, "warning": Fore.YELLOW, "error": Fore.RED}
        print(f"[{colors.get(level, '')}{level.upper()}{Style.RESET_ALL}] {message}")
    else:
        print(f"[{level.upper()}] {message}")

def safe_eval(expr):
    try:
        tree = ast.parse(expr.strip(), mode='eval')
        if not all(isinstance(n, (ast.Expression, ast.BinOp, ast.Num, ast.UnaryOp, ast.operator)) for n in ast.walk(tree)):
            return expr
        val = eval(compile(tree, '<string>', 'eval'), {"__builtins__": None}, {})
        return str(val)
    except Exception:
        return expr

class PrometheusStringDecryptor:
    def __init__(self):
        self.lcg_mult = 1103515245
        self.lcg_inc = 12345
        self.lcg_mod = 2**45
        self.xor_mult = 257
        self.xor_mod = 65537

    def decrypt(self, enc, seed):
        lcg = seed % self.lcg_mod
        xor = 1
        res = []
        for ch in enc:
            lcg = (lcg * self.lcg_mult + self.lcg_inc) % self.lcg_mod
            xor = (xor * self.xor_mult) % self.xor_mod
            if xor == 1:
                xor = (xor * self.xor_mult) % self.xor_mod
            key = (lcg + xor) % 256
            res.append(chr(ord(ch) ^ key))
        return ''.join(res)

def decrypt_prometheus_strings(code):
    decryptor = PrometheusStringDecryptor()
    pattern = r'function\s+([\w_]+)\s*\(\s*([\w_]+)\s*\)\s*local\s+[\w_]+\s*=\s*(\d+)'
    for func, _, seed_str in re.findall(pattern, code):
        seed = int(seed_str)
        call_pat = rf'{func}\s*\(\s*"([^"]+)"\s*\)'
        code = re.sub(call_pat, lambda m, s=seed: f'"{decryptor.decrypt(m.group(1), s)}"', code)
        log(f"Decrypted strings using {func}", "debug")
    return code

def resolve_constant_arrays(code):
    for match in re.finditer(r'local\s+([\w_]+)\s*=\s*{([^}]+)}', code, re.DOTALL):
        name, content = match.groups()
        elems = []
        for elem in re.split(r',\s*(?![^{]*})', content):
            elem = elem.strip()
            if elem.startswith(('"', "'")):
                elems.append(elem)
            elif elem.isdigit():
                elems.append(elem)
            else:
                elems.append('nil')
        for i, val in enumerate(elems, 1):
            code = re.sub(rf'{re.escape(name)}\[\s*{i}\s*\]', val, code)
        log(f"Resolved constant array {name}", "debug")
    return code

def remove_antitamper(code):
    patterns = [
        (r'pcall\s*\([^)]*\)\s*', ''),
        (r'debug\.getinfo\s*\([^)]*\)\s*', ''),
        (r'debug\.sethook\s*\([^)]*\)\s*', ''),
        (r'local valid=true;.*?if valid then else.*?end', 'local valid=true;'),
    ]
    for pat, repl in patterns:
        code = re.sub(pat, repl, code, flags=re.DOTALL)
    log("Removed anti‑tamper", "debug")
    return code

def simplify_control_flow(code):
    code = re.sub(r'else\s+if', 'elseif', code)
    code = re.sub(r'if\s+(\w+)\s+then\s+\1\s*=\s*\1\s+end', '', code)
    return code

def decode_accumulator_phases(code):
    phase_map = {
        '-11917660': 'INIT_PHASE',
        '4437436': 'STRING_DECODE_PHASE',
        '2400310': 'CRYPTO_PHASE',
        '11464279': 'MEMORY_PHASE',
        '10056034': 'BUFFER_PHASE',
    }
    for num, label in phase_map.items():
        code = re.sub(rf'accumulator\s*([<>]=?)\s*{num}', f'phase {label} \\1', code)
    return code

def devirtualize_bytecode(code):
    code = re.sub(r'goto\s*\[[\w_]+\]', '-- indirect goto removed', code)
    code = re.sub(r'while\s+true\s+do\s*(.*?)\s*end',
                  lambda m: f'-- VM loop removed\n{m.group(1)}', code, flags=re.DOTALL)
    return code

def demangle_names(code):
    mapping = {
        'V': 'table', 'f': 'func', 'R': 'string', 'O': 'math', 'N': 'num',
        'X': 'char', 'G': 'table_insert', 'p': 'string_sub', 'i': 'concat',
        't': 'accumulator', 'K': 'bit32', 'D': 'buffer', 'S': 'state',
    }
    for old, new in mapping.items():
        code = re.sub(rf'\b{old}\b(?![\'"])', new, code)
    code = re.sub(r'local_var_\d+', 'tmp_var', code)
    return code

def reconstruct_string_concat(code):
    def repl(m):
        parts = re.findall(r'"([^"]+)"', m.group(1))
        return '"' + ''.join(parts) + '"' if parts else m.group(0)
    code = re.sub(r'table\.concat\(\{([^}]+)\}\)', repl, code)
    return code

def remove_junk(code):
    patterns = [
        (r'local function \w+\(\)\s*return ""\s*end', ''),
        (r'if \w+ == -\d+ then \w+ = -\d+ end', ''),
        (r'for \w+ = -\d+,#\w+,-?\d+ do end', ''),
        (r'\w+ = \w+ [+-] \d+\s*$', '', re.MULTILINE),
        (r'local \w+ = nil\s*', ''),
    ]
    for pat, repl, *flags in patterns:
        flag = flags[0] if flags else 0
        code = re.sub(pat, repl, code, flags=flag)
    return code

def detect_phases(code):
    code = re.sub(r'--\s*\[(\w+)\]', r'-- PHASE_\1_START', code)
    code = re.sub(r'accumulator\s*=\s*(\d+)', lambda m: f'phase = {m.group(1)}', code)
    return code

def extract_base64_payloads(code):
    def decode_b64(m):
        try:
            data = base64.b64decode(m.group(1))
            return f'"{data.decode("utf-8", "replace")}"'
        except:
            return m.group(0)
    code = re.sub(r'"([A-Za-z0-9+/=]+)"\s*\.\.\s*"([A-Za-z0-9+/=]+)"', decode_b64, code)
    return code

def pretty_print(code):
    lines = []
    indent = 0
    for line in code.splitlines():
        line = line.strip()
        if line.startswith(('end', 'until', 'elseif', 'else')):
            indent = max(0, indent - 1)
        lines.append('    ' * indent + line)
        if line.endswith('then') or line.endswith('do') or line.startswith('function'):
            indent += 1
    return '\n'.join(lines)

def deobfuscate(code, verbose=False):
    steps = [
        ("Decrypting strings", decrypt_prometheus_strings),
        ("Resolving constant arrays", resolve_constant_arrays),
        ("Removing anti‑tamper", remove_antitamper),
        ("Simplifying control flow", simplify_control_flow),
        ("Decoding accumulator phases", decode_accumulator_phases),
        ("Devirtualizing bytecode", devirtualize_bytecode),
        ("Demangling names", demangle_names),
        ("Reconstructing string concat", reconstruct_string_concat),
        ("Removing junk code", remove_junk),
        ("Detecting phase boundaries", detect_phases),
        ("Extracting base64 payloads", extract_base64_payloads),
        ("Pretty printing", pretty_print),
    ]
    for name, func in steps:
        if verbose:
            log(f"Running: {name}", "debug")
        code = func(code)
    return code

def main():
    if len(sys.argv) < 2:
        print("Usage: python prometheus_deobf.py <input.lua> [output.lua]")
        sys.exit(1)
    infile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else infile.replace('.lua', '_deobf.lua')
    if not os.path.exists(infile):
        log(f"File not found: {infile}", "error")
        sys.exit(1)
    with open(infile, 'r', encoding='utf-8', errors='ignore') as f:
        code = f.read()
    verbose = '-v' in sys.argv or '--verbose' in sys.argv
    result = deobfuscate(code, verbose)
    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(result)
    log(f"Deobfuscated script written to {outfile}", "info")

if __name__ == "__main__":
    main()