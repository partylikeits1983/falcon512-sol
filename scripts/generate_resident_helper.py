#!/usr/bin/env python3
"""Wrap the pinned permutation with a resident replicated-lane interface.

800-byte input: 25 uint64 lanes, returned as 25 uint64 lanes (reference API).
832-byte input: ignored prefix word, then 25 rep4 lanes, returned as rep4 lanes.
Other lengths revert. The caller must preserve rep4 in the resident interface.
The permutation body is copied unchanged from the Fireblocks MIT artifact.
Run with --write to regenerate; by default check the committed runtime.
"""
from pathlib import Path
import hashlib
import sys

ROOT = Path(__file__).resolve().parents[1]
source = bytes.fromhex((ROOT / 'test/fixtures/f1600_170.hex').read_text().strip())
assert hashlib.sha256(source).hexdigest() == '4e5d23b7ceb7f06dcec538fb4c038f8ad04f133d46e57ea27b219a6eb68bce3b'
assert source[0x5A9] == 0x5B and source[0x4F26:0x4F2A] == bytes.fromhex('61003f56')
body = source[0x5AA:0x4F26]
# The body has no control flow or calldata dependence, so relocation is exact.
pc = 0
while pc < len(body):
    op = body[pc]
    assert op not in (0x35, 0x36, 0x37, 0x56, 0x57, 0x58, 0x5B, 0xF3, 0xFD)
    pc += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
assert pc == len(body)


def push(value):
    if value == 0:
        return b'\x5f'
    width = (value.bit_length() + 7) // 8
    return bytes([0x5F + width]) + value.to_bytes(width, 'big')


code = bytearray()
labels = {}
fixups = []


def ref(name):
    code.extend(b'\x61\x00\x00')
    fixups.append((len(code) - 2, name))


def label(name):
    labels[name] = len(code)
    code.extend(b'\x5b')


for length, entry in ((832, 'resident'), (800, 'clean')):
    code.extend(b'\x36' + push(length) + b'\x14')
    ref(entry)
    code.extend(b'\x57')
code.extend(b'\x5f\x5f\xfd')
label('resident')
code.extend(push(800) + push(32) + push(800) + b'\x37')
ref('body')
code.extend(b'\x56')
label('clean')
code.extend(push(sum(1 << (64 * i) for i in range(4))))
for i in range(25):
    code.extend(push(32 * i) + b'\x35\x81\x02' + push(800 + 32 * i) + b'\x52')
code.extend(b'\x50')
label('body')
code.extend(body)
code.extend(b'\x36' + push(832) + b'\x14')
ref('return')
code.extend(b'\x57')
code.extend(push((1 << 64) - 1))
for i in range(25):
    code.extend(push(800 + 32 * i) + b'\x51\x81\x16' + push(800 + 32 * i) + b'\x52')
code.extend(b'\x50')
label('return')
code.extend(push(800) + b'\x80\xf3')
for offset, name in fixups:
    assert code[labels[name]] == 0x5B
    code[offset:offset + 2] = labels[name].to_bytes(2, 'big')
assert len(code) <= 24576
path = ROOT / 'test/fixtures/f1600_resident.hex'
if '--write' in sys.argv:
    path.write_text(code.hex())
else:
    assert bytes.fromhex(path.read_text().strip()) == code, 'regenerate resident helper'
print(f'Resident helper: {len(code)} bytes; unchanged pinned permutation verified')
