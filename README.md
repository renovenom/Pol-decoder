# Pol-decoder – Prometheus Lua Deobfuscator

A Python tool to reverse obfuscation applied by the **Prometheus Lua Obfuscator**.

## Features

- String decryption (dual PRNG – LCG + XOR)
- Constant array inlining
- Anti‑tamper removal (`pcall`, `debug.getinfo`, `debug.sethook`)
- Control flow simplification
- VM / accumulator phase decoding
- Bytecode devirtualization (basic)
- Name demangling
- String concatenation reconstruction
- Junk code removal
- Base64 payload extraction
- Pretty printing

## Requirements

Python 3.6+  
Optional: `colorama`, `networkx` (install via `pip install -r requirements.txt`)

## Usage

```bash
python prometheus_deobf.py obfuscated.lua [output.lua]