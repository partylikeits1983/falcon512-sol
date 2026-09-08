"""Independent SHAKE256/Falcon rejection-sampling oracle using Python hashlib."""

import hashlib
import sys

data = bytes.fromhex(sys.argv[1].removeprefix("0x"))
size = 1088
while True:
    stream = hashlib.shake_256(data).digest(size)
    values = [int.from_bytes(stream[i : i + 2], "big") for i in range(0, size, 2)]
    accepted = [value % 12289 for value in values if value < 5 * 12289]
    if len(accepted) >= 512:
        print("0x" + b"".join(value.to_bytes(2, "big") for value in accepted[:512]).hex())
        break
    size += 136
