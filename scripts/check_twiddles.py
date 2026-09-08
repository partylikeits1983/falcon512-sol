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
print("NTT twiddle tables and fused normalization constant verified")
