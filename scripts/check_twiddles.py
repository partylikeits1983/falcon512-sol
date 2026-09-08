"""Check the NTT tables independently from their field definitions."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
Q = 12289
forward = [pow(49, int(f"{i:09b}"[::-1], 2), Q) for i in range(512)]
inverse = [pow(value, Q - 2, Q) for value in forward]


def encoded(values):
    return b"".join(value.to_bytes(2, "big") for value in values)


def tables(name):
    return [bytes.fromhex(value) for value in re.findall(r'hex"([0-9a-f]+)"', (ROOT / name).read_text())]


assert tables("src/FalconNTT.sol") == [encoded(forward), encoded(inverse)]
fused = forward[:128] + inverse[:128]
for word in range(128):
    for index in (128 + word, 256 + 2 * word, 257 + 2 * word):
        fused.extend((forward[index], inverse[index]))
assert tables("src/FalconNTTFused.sol") == [encoded(fused)]
assert inverse[1] * pow(512, -1, Q) % Q == 1371

R = 1 << 16
forward_mont = [value * R % Q for value in forward]
inverse_mont = [value * R % Q for value in inverse]
wide = forward_mont[:64] + inverse_mont[:64]
for word in range(64):
    wide.extend((forward_mont[64 + word], inverse_mont[64 + word]))
    for half in range(2):
        index = 128 + 2 * word + half
        wide.extend((forward_mont[index], inverse_mont[index]))
        for index in (256 + 4 * word + 2 * half, 257 + 4 * word + 2 * half):
            wide.extend((forward[index], inverse[index]))
assert tables("src/FalconNTTMontgomery.sol") == [encoded(wide)]
assert -pow(Q, -1, R) % R == 12287
assert pow(512, -1, Q) * R % Q == 128
assert inverse[1] * pow(512, -1, Q) * R % Q == 4977

# Conservative integer inequalities proving the documented lane bounds.
# REDC(x) <= floor((x + (R-1)*q)/R); each correction fits one 32-bit lane.
bound = 1
for bias in (2, 2, 2, 3, 3, 4):
    max_product = (bound * Q - 1) * (Q - 1)
    assert max_product + (R - 1) * Q < 1 << 32
    assert (max_product + (R - 1) * Q) // R < bias * Q
    bound += bias
assert bound == 17
assert (R - 1) * 12287 < 1 << 32
assert (17 * Q - 1) * 21 < 1 << 32
assert 21 == (1 << 18) // Q
assert 17 * ((1 << 18) - 21 * Q) < 1 << 18
inverse_max = (8 * Q - 1) * (Q - 1) + (R - 1) * Q
assert inverse_max < 1 << 32 and inverse_max // R < 4 * Q
for factor in (128, 4977):
    assert ((8 * Q - 1) * factor + (R - 1) * Q) // R < 2 * Q

# Packed norm: exhaustive scalar centering and convolution carry bounds.
for coefficient in range(Q):
    sign = (coefficient + 0x67ff) >> 15
    centered = ((coefficient ^ (sign * 65535)) + sign * (Q + 1)) & 65535
    assert centered == min(coefficient, Q - coefficient)
    folded = (coefficient + Q // 2) % Q - Q // 2
    assert folded * folded == centered * centered
assert 30722 == 2 * Q + Q // 2
assert 8 * (Q // 2) ** 2 < 1 << 32
assert 512 * (Q // 2) ** 2 < 1 << 256
# Four-candidate rejection mask: low-15-bit addition stays within uint16.
assert 0x7FFF + 0x0FFB < 1 << 16
for candidate in range(1 << 16):
    rejected = ((candidate & 0x7FFF) + 0x0FFB) & candidate & 0x8000
    assert bool(rejected) == (candidate >= 5 * Q)
print("NTT tables, field constants, and packed-lane bounds verified")
