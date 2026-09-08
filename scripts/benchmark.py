#!/usr/bin/env python3
"""Measure verification of 32-byte Keccak-256 digests on a private Anvil instance.

--lengths selects the source message sizes, before hashing. Falcon always signs
the 32 raw digest bytes; only those digest bytes are sent to the verifier.

Run `cargo build -p falcon512-oracle && forge build` first. No external RPC,
wallet, private key, or Python dependency is used. Anvil is stopped on exit.
"""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
Q = 12289


def word(value):
    return value.to_bytes(32, "big")


def compact(values):
    return [sum(values[i + j] << (16 * j) for j in range(16)) for i in range(0, 512, 16)]


def prepare(signature, public_key):
    assert len(signature) == 666 and signature[0] == 0x59
    assert len(public_key) == 897 and public_key[0] == 9
    bits = int.from_bytes(signature[41:], "big")
    remaining = 625 * 8

    def read(count):
        nonlocal remaining
        remaining -= count
        assert remaining >= 0
        return (bits >> remaining) & ((1 << count) - 1)

    s2 = []
    for _ in range(512):
        byte = read(8)
        magnitude = byte & 127
        while read(1) == 0:
            magnitude += 128
        assert magnitude <= 2047 and not (byte & 128 and magnitude == 0)
        s2.append(Q - magnitude if byte & 128 else magnitude)
    assert bits & ((1 << remaining) - 1) == 0

    bits = int.from_bytes(public_key[1:], "big")
    h = [(bits >> (14 * (511 - i))) & 0x3FFF for i in range(512)]
    assert all(coefficient < Q for coefficient in h)
    t = 512
    m = 1
    while m < 512:
        t //= 2
        for i in range(m):
            reverse = int(f"{m + i:09b}"[::-1], 2)
            twiddle = pow(49, reverse, Q)
            for j in range(2 * i * t, (2 * i + 1) * t):
                u, v = h[j], h[j + t] * twiddle % Q
                h[j], h[j + t] = (u + v) % Q, (u - v) % Q
        m *= 2
    return signature[1:41], compact(s2), compact(h)


def encode_call(selector, message, salt, s2, key):
    def dynamic_bytes(data):
        return word(len(data)) + data + bytes((-len(data)) % 32)

    tails = [dynamic_bytes(message), dynamic_bytes(salt)]
    tails += [word(len(values)) + b"".join(map(word, values)) for values in (s2, key)]
    offset = 128
    offsets = []
    for tail in tails:
        offsets.append(word(offset))
        offset += len(tail)
    return selector + b"".join(offsets + tails)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hardfork", default="shanghai")
    parser.add_argument(
        "--lengths", type=int, nargs="+", default=[0, 16, 95, 96, 232, 512, 1024],
        help="source message lengths before Keccak-256 (signed input is always 32 bytes)",
    )
    args = parser.parse_args()
    assert all(0 <= length <= 4096 for length in args.lengths)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    def rpc(method, params):
        data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}", data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result["result"]

    with tempfile.TemporaryFile() as log:
        node = subprocess.Popen(
            ["anvil", "--host", "127.0.0.1", "--port", str(port), "--hardfork", args.hardfork],
            stdout=log,
            stderr=log,
        )
        try:
            for _ in range(100):
                if node.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read().decode())
                try:
                    accounts = rpc("eth_accounts", [])
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Anvil did not start")

            def send(data, to=None, gas=10_000_000):
                transaction = {"from": accounts[0], "data": "0x" + data.hex(), "gas": hex(gas)}
                if to:
                    transaction["to"] = to
                    assert int(rpc("eth_call", [transaction, "latest"]), 16) == 1
                tx_hash = rpc("eth_sendTransaction", [transaction])
                for _ in range(200):
                    receipt = rpc("eth_getTransactionReceipt", [tx_hash])
                    if receipt is not None:
                        break
                    time.sleep(0.05)
                else:
                    raise RuntimeError(f"Transaction was not mined: {tx_hash}")
                assert int(receipt["status"], 16) == 1, receipt
                return receipt

            runtime = bytes.fromhex((ROOT / "test/fixtures/f1600_resident.hex").read_text().strip())
            init = b"\x61" + len(runtime).to_bytes(2, "big") + bytes.fromhex("8061000d6000396000f3") + runtime
            helper_receipt = send(init)
            helper = helper_receipt["contractAddress"]
            artifact = json.loads((ROOT / "out/Falcon512Verifier.sol/Falcon512Verifier.json").read_text())
            init = bytes.fromhex(artifact["bytecode"]["object"].removeprefix("0x")) + word(int(helper, 16))
            verifier_receipt = send(init)
            verifier = verifier_receipt["contractAddress"]
            selector = bytes.fromhex(
                subprocess.check_output(
                    ["cast", "sig", "verifyPrepared(bytes,bytes,uint256[],uint256[])"], text=True
                ).strip().removeprefix("0x")
            )
            print(json.dumps({
                "hardfork": args.hardfork,
                "helper_deployment_gas": int(helper_receipt["gasUsed"], 16),
                "verifier_deployment_gas": int(verifier_receipt["gasUsed"], 16),
                "runtime_bytes": len(bytes.fromhex(rpc("eth_getCode", [verifier, "latest"])[2:])),
            }), flush=True)
            for length in args.lengths:
                source_message = bytes.fromhex("00112233445566778899aabbccddeeff") if length == 16 else bytes(
                    i % 256 for i in range(length)
                )
                message = bytes.fromhex(subprocess.check_output(
                    ["cast", "keccak", "0x" + source_message.hex()], text=True
                ).strip().removeprefix("0x"))
                assert len(message) == 32
                generated = bytes.fromhex(subprocess.check_output([
                    str(ROOT / "target/debug/falcon512-oracle"), "gen", "0x" + word(0x42).hex(),
                    "0x" + word(0x99).hex(), "0x" + message.hex(),
                ], text=True).strip().removeprefix("0x"))
                salt, s2, key = prepare(generated[:666], generated[666:])
                call = encode_call(selector, message, salt, s2, key)
                receipt = send(call, verifier, gas=1_000_000)
                intrinsic = 21_000 + sum(4 if byte == 0 else 16 for byte in call)
                gas_used = int(receipt["gasUsed"], 16)
                print(json.dumps({
                    "source_message_bytes": length, "signed_message_bytes": len(message),
                    "transaction_gas": gas_used,
                    "intrinsic_gas": intrinsic, "execution_gas": gas_used - intrinsic,
                }), flush=True)
        finally:
            node.terminate()
            try:
                node.wait(timeout=5)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait()


if __name__ == "__main__":
    main()
