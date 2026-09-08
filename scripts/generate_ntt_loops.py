#!/usr/bin/env python3
"""Check or regenerate the fully unrolled word butterflies.

Run with --write, then forge fmt, to regenerate. By default, check the existing
source while ignoring whitespace/comments. Field arithmetic is independently
checked by check_twiddles.py and the differential arithmetic tests.
"""

import argparse
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/FalconNTTMontgomery.sol"


def butterfly(offset, width, bias=None):
    text = f"""{{
        let pa := add(p, {offset})
        let pt := add(pa, {32 * width})
        let u := mload(pa)
    """
    if bias is not None:
        text += f"""
            let v := mont(mul(mload(pt), s))
            mstore(pa, add(u, v))
            mstore(pt, sub(add(u, _Q{bias}L32), v))
        """
    else:
        text += """
            let v := mload(pt)
            let d := mont(mul(sub(add(u, _Q4L32), v), s))
            mstore(pa, bound4q(add(u, v)))
            mstore(pt, d)
        """
    return text + "}\n"


def stages(inverse=False):
    output = "{\n"
    if inverse:
        output += "let inverse := add(table, 128)\n"
    widths = (1, 2, 4, 8, 16) if inverse else (32, 16, 8, 4, 2, 1)
    table = "inverse" if inverse else "table"
    for width in widths:
        groups = 32 // width
        if groups == 1:
            output += "{ let p := base\nlet s := shr(240, mload(add(table, 2)))\n"
        else:
            output += f"""
                for {{ let w := 0 }} lt(w, {groups}) {{ w := add(w, 1) }} {{
                    let p := add(base, mul({64 * width}, w))
                    let s := shr(240, mload(add(add({table}, {2 * groups}), shl(1, w))))
            """
        bias = None if inverse else (2 if groups < 8 else 3 if groups < 32 else 4)
        output += "".join(butterfly(32 * j, width, bias) for j in range(width))
        output += "}\n"
    return output + "}\n"


def normalization():
    output = "{ let p := base\n"
    for j in range(32):
        output += f"""{{
            let pa := add(p, {32 * j})
            let pt := add(pa, 1024)
            let u := mload(pa)
            let v := mload(pt)
            mstore(pa, mont(shl(7, add(u, v))))
            mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
        }}
        """
    return output + "}\n"


def tokens(text):
    return re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", text))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    source = SOURCE.read_text()
    for name, generated in (
        ("FORWARD", stages()),
        ("INVERSE", stages(inverse=True)),
        ("NORMALIZE", normalization()),
    ):
        start = source.index(f"// BEGIN GENERATED {name}\n") + len(f"// BEGIN GENERATED {name}\n")
        end = source.index(f"// END GENERATED {name}", start)
        if args.write:
            source = source[:start] + generated + source[end:]
        else:
            assert tokens(source[start:end]) == tokens(generated), f"{name} differs from generated butterflies"
    if args.write:
        SOURCE.write_text(source)
    else:
        print("Unrolled forward, inverse, and normalization butterflies verified")


if __name__ == "__main__":
    main()
