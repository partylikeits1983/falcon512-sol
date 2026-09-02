// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

interface IFalcon512Verifier {
    function verify(bytes calldata signature, bytes calldata publicKey, bytes calldata message)
        external
        view
        returns (bool);
}

contract Falcon512DifferentialTest is Test {
    uint256 private constant SIG_LEN = 666;
    uint256 private constant PK_LEN = 897;
    uint256 private constant Q = 12289;

    IFalcon512Verifier private verifier;

    function setUp() public {
        address tables = deployCode("Falcon512Tables.sol:Falcon512Tables");
        verifier = IFalcon512Verifier(deployCode("Falcon512Verifier.sol:Falcon512Verifier", abi.encode(tables)));
    }

    function test_RustGeneratedSignatureVerifies() public {
        bytes memory message = hex"00112233445566778899aabbccddeeff";
        (bytes memory signature, bytes memory publicKey) =
            _rustGenerate(bytes32(uint256(0x42)), bytes32(uint256(0x99)), message);

        assertTrue(_rustVerify(signature, publicKey, message), "rust oracle sanity check failed");
        assertTrue(verifier.verify(signature, publicKey, message), "solidity rejected rust-valid signature");
    }

    function test_RustRejectsWrongMessage() public {
        bytes memory message = hex"feedfacedeadbeef";
        (bytes memory signature, bytes memory publicKey) =
            _rustGenerate(bytes32(uint256(0x01)), bytes32(uint256(0x02)), message);
        bytes memory wrongMessage = hex"feedfacedeadbeee";

        assertFalse(_rustVerify(signature, publicKey, wrongMessage), "rust accepted wrong message");
        assertFalse(verifier.verify(signature, publicKey, wrongMessage), "solidity accepted wrong message");
    }

    function test_RegressPublicKeyBitFlipAgainstRustBound() public {
        bytes32 keySeed = 0x6d425fb2cf29073c76ef77defde47326fc05b084f462e334b265dd691e5233ca;
        bytes32 rngSeed = 0x895deda1ba491b00dce4b70e152fbc17e21247215bfb4963a0801196b7f9b3e9;
        bytes32 msgSeed = 0xd07f270838bdfe522b2bcd48c13b34dbb7b88e7d447a517168068242d72e94ee;
        bytes memory message = _messageFromSeed(msgSeed, 13);
        (bytes memory signature, bytes memory publicKey) = _rustGenerate(keySeed, rngSeed, message);
        publicKey = _flip(publicKey, 7, 1);

        assertFalse(_rustVerify(signature, publicKey, message), "rust accepted mutated public key");
        assertFalse(verifier.verify(signature, publicKey, message), "solidity accepted mutated public key");
    }

    function test_RustAcceptsNonCanonicalPublicKeyChunk() public {
        bytes memory message = hex"00112233445566778899aabbccddeeff";
        (bytes memory signature, bytes memory publicKey) =
            _rustGenerate(bytes32(uint256(0x42)), bytes32(uint256(0x99)), message);
        publicKey = _addQToPublicKeyCoefficient(publicKey, 1);

        assertTrue(_rustVerify(signature, publicKey, message), "rust rejected equivalent public key");
        assertTrue(verifier.verify(signature, publicKey, message), "solidity rejected equivalent public key");
    }

    function testFuzz_DifferentialMutations(
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
        bool solidityResult = verifier.verify(signature, publicKey, message);
        assertEq(solidityResult, rustResult, "solidity/rust verification mismatch");
    }

    function _rustGenerate(bytes32 keySeed, bytes32 rngSeed, bytes memory message)
        internal
        returns (bytes memory signature, bytes memory publicKey)
    {
        string[] memory cmd = new string[](10);
        cmd[0] = "cargo";
        cmd[1] = "run";
        cmd[2] = "--quiet";
        cmd[3] = "-p";
        cmd[4] = "falcon512-oracle";
        cmd[5] = "--";
        cmd[6] = "gen";
        cmd[7] = vm.toString(keySeed);
        cmd[8] = vm.toString(rngSeed);
        cmd[9] = vm.toString(message);

        bytes memory out = vm.ffi(cmd);
        assertEq(out.length, SIG_LEN + PK_LEN, "invalid oracle gen output length");

        signature = _slice(out, 0, SIG_LEN);
        publicKey = _slice(out, SIG_LEN, PK_LEN);
    }

    function _rustVerify(bytes memory signature, bytes memory publicKey, bytes memory message)
        internal
        returns (bool)
    {
        string[] memory cmd = new string[](10);
        cmd[0] = "cargo";
        cmd[1] = "run";
        cmd[2] = "--quiet";
        cmd[3] = "-p";
        cmd[4] = "falcon512-oracle";
        cmd[5] = "--";
        cmd[6] = "verify";
        cmd[7] = vm.toString(signature);
        cmd[8] = vm.toString(publicKey);
        cmd[9] = vm.toString(message);

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

    function _addQToPublicKeyCoefficient(bytes memory publicKey, uint256 coefficientIndex)
        internal
        pure
        returns (bytes memory out)
    {
        out = _copy(publicKey);
        uint256 value = _readPublicKeyCoefficient(out, coefficientIndex);
        require(value + Q < 1 << 14, "coefficient too large");
        _writePublicKeyCoefficient(out, coefficientIndex, value + Q);
    }

    function _readPublicKeyCoefficient(bytes memory publicKey, uint256 coefficientIndex)
        internal
        pure
        returns (uint256 value)
    {
        uint256 bitOffset = 8 + coefficientIndex * 14;
        for (uint256 i = 0; i < 14; ++i) {
            value = (value << 1) | _readBit(publicKey, bitOffset + i);
        }
    }

    function _writePublicKeyCoefficient(bytes memory publicKey, uint256 coefficientIndex, uint256 value)
        internal
        pure
    {
        uint256 bitOffset = 8 + coefficientIndex * 14;
        for (uint256 i = 0; i < 14; ++i) {
            _writeBit(publicKey, bitOffset + i, (value >> (13 - i)) & 1);
        }
    }

    function _readBit(bytes memory input, uint256 bitOffset) internal pure returns (uint256) {
        return (uint8(input[bitOffset >> 3]) >> (7 - (bitOffset & 7))) & 1;
    }

    function _writeBit(bytes memory input, uint256 bitOffset, uint256 bit) internal pure {
        uint256 byteIndex = bitOffset >> 3;
        uint8 mask = uint8(1 << (7 - (bitOffset & 7)));
        uint8 current = uint8(input[byteIndex]);
        if (bit == 0) {
            current &= ~mask;
        } else {
            current |= mask;
        }
        input[byteIndex] = bytes1(current);
    }
}
