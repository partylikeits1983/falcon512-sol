// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {Falcon512ZKNOXOptimized} from "../src/Falcon512ZKNOXOptimized.sol";
import {_ZKNOX_NTT_Compact} from "../src/ZKNOX_falcon_utils.sol";
import {
    _compactFromPacked,
    _nttFwPacked,
    _nttInvPacked,
    _packFromCompact,
    _unpackTo512,
    _vecMulPacked
} from "../src/ZKNOX_NTT_falcon_packed.sol";
import {hashToPointNISTFast} from "../src/ZKNOX_shake_fast.sol";

contract Falcon512ZKNOXOptimizedTest is Test {
    uint256 private constant SIG_LEN = 666;
    uint256 private constant PK_LEN = 897;
    uint256 private constant Q = 12289;

    Falcon512ZKNOXOptimized private optimized;

    function setUp() public {
        address helper = _deployF1600Helper();
        optimized = new Falcon512ZKNOXOptimized(helper);
    }

    function test_RustGeneratedPreparedSignatureVerifies() public {
        bytes memory message = hex"00112233445566778899aabbccddeeff";
        (bytes memory signature, bytes memory publicKey) =
            _rustGenerate(bytes32(uint256(0x42)), bytes32(uint256(0x99)), message);

        (bool prepared, bytes memory salt, uint256[] memory s2, uint256[] memory ntth) = _prepare(signature, publicKey);

        assertTrue(prepared, "prepare failed");
        assertTrue(_rustVerify(signature, publicKey, message), "rust rejected valid signature");
        assertTrue(optimized.verifyPrepared(message, salt, s2, ntth), "optimized rejected valid signature");
    }

    function test_UpstreamHashToPointVector() public view {
        bytes memory salt =
            "\x4b\x09\x9f\x8e\x30\x0f\x01\xb8\x65\x0f\x1f\x4b\x1d\x8f\xcf\x3f\x3c\xb5\x3f\xb8\xe9\xeb\x2e\xa2\x03\xbd\xc9\x70\xf5\x0a\xe5\x54\x28\xa9\x1f\x7f\x53\xac\x26\x6b";
        bytes memory message = "My name is Renaud from ZKNOX!!!!";

        uint256[] memory hash = hashToPointNISTFast(salt, message, optimized.f1600Helper());

        assertEq(hash[0], 2578, "hash[0]");
        assertEq(hash[511], 11296, "hash[511]");
    }

    function test_PackedCoreAcceptsRustVector() public {
        bytes memory message = hex"00112233445566778899aabbccddeeff";
        (bytes memory signature, bytes memory publicKey) =
            _rustGenerate(bytes32(uint256(0x42)), bytes32(uint256(0x99)), message);

        (bool pkOk, uint256[] memory h) = _decodePublicKey(publicKey);
        (bool sigOk, uint256[] memory expandedS2) = _decodeSignature(signature);
        (bool prepared, bytes memory salt, uint256[] memory s2, uint256[] memory ntth) = _prepare(signature, publicKey);

        assertTrue(pkOk, "pk decode");
        assertTrue(sigOk, "sig decode");
        assertTrue(prepared, "prepare failed");
        assertEq(h[0], 7565, "h[0]");
        assertEq(h[1], 1695, "h[1]");
        assertEq(expandedS2[0], 77, "s2[0]");
        assertEq(expandedS2[1], Q - 34, "s2[1]");

        uint256[] memory hashed = hashToPointNISTFast(salt, message, optimized.f1600Helper());
        assertEq(hashed[0], 10936, "hash[0]");
        assertEq(hashed[1], 6886, "hash[1]");

        uint256[] memory product = _packedProduct(s2, ntth);
        assertEq(product[0], 10997, "product[0]");
        assertEq(product[1], 7135, "product[1]");
        assertEq(_norm(product, s2, hashed), 27825859, "norm");

        assertTrue(optimized.verifyPrepared(message, salt, s2, ntth), "packed core");
    }

    function test_RustRejectsWrongMessagePrepared() public {
        bytes memory message = hex"feedfacedeadbeef";
        (bytes memory signature, bytes memory publicKey) =
            _rustGenerate(bytes32(uint256(0x01)), bytes32(uint256(0x02)), message);
        bytes memory wrongMessage = hex"feedfacedeadbeee";

        (bool prepared, bytes memory salt, uint256[] memory s2, uint256[] memory ntth) = _prepare(signature, publicKey);

        assertTrue(prepared, "prepare failed");
        assertFalse(_rustVerify(signature, publicKey, wrongMessage), "rust accepted wrong message");
        assertFalse(optimized.verifyPrepared(wrongMessage, salt, s2, ntth), "optimized accepted wrong message");
    }

    function testFuzz_PreparedDifferentialMutations(
        bytes32 keySeed,
        bytes32 rngSeed,
        bytes32 msgSeed,
        uint8 msgLenByte,
        uint8 modeByte,
        uint16 index,
        uint8 mask
    ) public {
        bytes memory message = _messageFromSeed(msgSeed, msgLenByte);
        (bytes memory signature, bytes memory publicKey) = _rustGenerate(keySeed, rngSeed, message);

        uint8 mode = modeByte % 8;
        uint8 nonzeroMask = mask == 0 ? uint8(1) : mask;

        if (mode == 1) {
            signature = _flip(signature, index % uint16(SIG_LEN), nonzeroMask);
        } else if (mode == 2) {
            publicKey = _flip(publicKey, index % uint16(PK_LEN), nonzeroMask);
        } else if (mode == 3) {
            message = _flipOrAppend(message, index, nonzeroMask);
        } else if (mode == 4) {
            signature = _truncate(signature, index % uint16(SIG_LEN));
        } else if (mode == 5) {
            publicKey = _truncate(publicKey, index % uint16(PK_LEN));
        } else if (mode == 6) {
            signature = _setFirstByte(signature, 0x39);
        } else if (mode == 7) {
            signature = bytes.concat(signature, bytes1(nonzeroMask));
        }

        bool rustResult = _rustVerify(signature, publicKey, message);
        bool optimizedResult;

        (bool prepared, bytes memory salt, uint256[] memory s2, uint256[] memory ntth) = _prepare(signature, publicKey);
        if (prepared) {
            optimizedResult = optimized.verifyPrepared(message, salt, s2, ntth);
        }

        assertEq(optimizedResult, rustResult, "optimized/rust verification mismatch");
    }

    function _deployF1600Helper() internal returns (address helper) {
        string[] memory cmds = new string[](3);
        cmds[0] = "awk";
        cmds[1] = "{print \"0x\"$0}";
        cmds[2] = "test/fixtures/f1600_170.hex";
        bytes memory runtime = vm.ffi(cmds);
        bytes memory initCode = abi.encodePacked(hex"61", uint16(runtime.length), hex"8061000d6000396000f3", runtime);

        assembly {
            helper := create(0, add(initCode, 32), mload(initCode))
        }
        require(helper != address(0), "f1600 helper create failed");
        require(helper.code.length == 21622, "wrong f1600 helper size");
    }

    function _prepare(bytes memory signature, bytes memory publicKey)
        internal
        pure
        returns (bool ok, bytes memory salt, uint256[] memory s2, uint256[] memory ntth)
    {
        if (signature.length != SIG_LEN || publicKey.length != PK_LEN) {
            return (false, salt, s2, ntth);
        }
        if (signature[0] != 0x59 || publicKey[0] != 0x09) {
            return (false, salt, s2, ntth);
        }

        (bool pkOk, uint256[] memory h) = _decodePublicKey(publicKey);
        if (!pkOk) {
            return (false, salt, s2, ntth);
        }

        (bool sigOk, uint256[] memory expandedS2) = _decodeSignature(signature);
        if (!sigOk) {
            return (false, salt, s2, ntth);
        }

        salt = _slice(signature, 1, 40);
        s2 = _ZKNOX_NTT_Compact(expandedS2);
        ntth = _nttPublicKey(h);
        ok = true;
    }

    function _nttPublicKey(uint256[] memory h) internal pure returns (uint256[] memory) {
        return _compactFromPacked(_nttFwPacked(_packFromCompact(_ZKNOX_NTT_Compact(h))));
    }

    function _packedProduct(uint256[] memory s2, uint256[] memory ntth) internal pure returns (uint256[] memory) {
        return _unpackTo512(_nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(s2)), _packFromCompact(ntth))));
    }

    function _decodePublicKey(bytes memory publicKey) internal pure returns (bool ok, uint256[] memory h) {
        h = new uint256[](512);
        uint256 acc;
        uint256 accLen;
        uint256 byteIndex = 1;

        for (uint256 u = 0; u < 512;) {
            acc = (acc << 8) | uint8(publicKey[byteIndex++]);
            accLen += 8;
            if (accLen >= 14) {
                accLen -= 14;
                uint256 w = (acc >> accLen) & 0x3FFF;
                if (w >= Q) {
                    w -= Q;
                }
                h[u++] = w;
                acc &= (uint256(1) << accLen) - 1;
            }
        }

        ok = acc == 0;
    }

    function _decodeSignature(bytes memory signature) internal pure returns (bool ok, uint256[] memory s2) {
        s2 = new uint256[](512);
        uint256 bitIndex;
        uint256 bitLen = 625 * 8;

        for (uint256 u = 0; u < 512; ++u) {
            if (bitIndex + 8 > bitLen) {
                return (false, s2);
            }

            uint256 b = _getSignatureByte(signature, 41, bitIndex);
            bitIndex += 8;
            uint256 sign = b & 128;
            uint256 m = b & 127;

            while (true) {
                if (bitIndex >= bitLen) {
                    return (false, s2);
                }
                uint256 bit = _getSignatureBit(signature, 41, bitIndex);
                bitIndex++;
                if (bit != 0) {
                    break;
                }

                m += 128;
                if (m > 2047) {
                    return (false, s2);
                }
            }

            if (sign != 0 && m == 0) {
                return (false, s2);
            }
            s2[u] = sign != 0 ? Q - m : m;
        }

        while (bitIndex < bitLen) {
            if (_getSignatureBit(signature, 41, bitIndex) != 0) {
                return (false, s2);
            }
            bitIndex++;
        }

        ok = true;
    }

    function _getSignatureBit(bytes memory input, uint256 offset, uint256 bitIndex) internal pure returns (uint256) {
        return (uint8(input[offset + (bitIndex >> 3)]) >> (7 - (bitIndex & 7))) & 1;
    }

    function _getSignatureByte(bytes memory input, uint256 offset, uint256 bitIndex) internal pure returns (uint256) {
        uint256 byteIndex = offset + (bitIndex >> 3);
        uint256 shift = bitIndex & 7;
        uint256 word = uint256(uint8(input[byteIndex])) << 8;
        if (shift != 0) {
            word |= uint8(input[byteIndex + 1]);
        }
        return (word >> (8 - shift)) & 0xFF;
    }

    function _rustGenerate(bytes32 keySeed, bytes32 rngSeed, bytes memory message)
        internal
        returns (bytes memory signature, bytes memory publicKey)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "./target/debug/falcon512-oracle";
        cmd[1] = "gen";
        cmd[2] = vm.toString(keySeed);
        cmd[3] = vm.toString(rngSeed);
        cmd[4] = vm.toString(message);

        bytes memory out = vm.ffi(cmd);
        assertEq(out.length, SIG_LEN + PK_LEN, "invalid oracle gen output length");

        signature = _slice(out, 0, SIG_LEN);
        publicKey = _slice(out, SIG_LEN, PK_LEN);
    }

    function _rustVerify(bytes memory signature, bytes memory publicKey, bytes memory message)
        internal
        returns (bool)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "./target/debug/falcon512-oracle";
        cmd[1] = "verify";
        cmd[2] = vm.toString(signature);
        cmd[3] = vm.toString(publicKey);
        cmd[4] = vm.toString(message);

        bytes memory out = vm.ffi(cmd);
        assertEq(out.length, 1, "invalid oracle verify output length");
        return out[0] == bytes1(uint8(1));
    }

    function _messageFromSeed(bytes32 seed, uint8 lenByte) internal pure returns (bytes memory message) {
        uint256 len = uint256(lenByte % 96);
        message = new bytes(len);
        bytes32 blockHash = seed;
        for (uint256 i = 0; i < len; ++i) {
            if (i % 32 == 0) {
                blockHash = keccak256(abi.encodePacked(seed, i));
            }
            message[i] = blockHash[i % 32];
        }
    }

    function _flip(bytes memory input, uint256 index, uint8 mask) internal pure returns (bytes memory out) {
        out = _copy(input);
        out[index] = bytes1(uint8(out[index]) ^ mask);
    }

    function _flipOrAppend(bytes memory input, uint256 index, uint8 mask) internal pure returns (bytes memory out) {
        if (input.length == 0) {
            return bytes.concat(input, bytes1(mask));
        }
        return _flip(input, index % input.length, mask);
    }

    function _setFirstByte(bytes memory input, uint8 value) internal pure returns (bytes memory out) {
        out = _copy(input);
        out[0] = bytes1(value);
    }

    function _truncate(bytes memory input, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = input[i];
        }
    }

    function _slice(bytes memory input, uint256 offset, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; ++i) {
            out[i] = input[offset + i];
        }
    }

    function _copy(bytes memory input) internal pure returns (bytes memory out) {
        out = new bytes(input.length);
        for (uint256 i = 0; i < input.length; ++i) {
            out[i] = input[i];
        }
    }

    function _norm(uint256[] memory product, uint256[] memory s2, uint256[] memory hashed)
        internal
        pure
        returns (uint256 total)
    {
        for (uint256 i = 0; i < 512; ++i) {
            uint256 x = addmod(hashed[i], Q - product[i], Q);
            if (x > Q / 2) x = Q - x;
            total += x * x;
        }
        for (uint256 i = 0; i < 32; ++i) {
            uint256 packed = s2[i];
            for (uint256 j = 0; j < 16; ++j) {
                uint256 x = (packed >> (j << 4)) & 0xffff;
                if (x > Q / 2) x = Q - x;
                total += x * x;
            }
        }
    }
}
