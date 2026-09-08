// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {
    _sampleShakeBlockNormPacked,
    _sampleShakeBlockNormPacked8,
    _sampleShakeStateNormPacked8
} from "../src/FalconShake.sol";

contract ShakeSamplingTest is Test {
    uint256 private constant Q = 12289;

    function testFuzz_SamplingAgainstScalar(bytes32 seed, uint16 initialCount) public pure {
        uint256[] memory product = new uint256[](128);
        for (uint256 i; i < 512; ++i) {
            uint256 coefficient = uint256(keccak256(abi.encode(seed, i))) % (2 * Q);
            product[i / 4] |= coefficient << (64 * (i % 4));
        }
        bytes memory blockData = new bytes(160);
        for (uint256 i; i < 5; ++i) {
            bytes32 word = keccak256(abi.encode(seed, i, uint256(1)));
            assembly ("memory-safe") {
                mstore(add(add(blockData, 32), mul(i, 32)), word)
            }
        }
        _check(product, blockData, uint256(initialCount) % 513, uint256(seed) % 34034726);
    }

    function test_SamplingBoundaries() public pure {
        uint256[] memory product = new uint256[](128);
        for (uint256 i; i < 128; ++i) {
            product[i] = (2 * Q - 1) * (1 + (uint256(1) << 64) + (uint256(1) << 128) + (uint256(1) << 192));
        }
        uint256[6] memory candidates = [uint256(0), Q - 1, Q, 5 * Q - 1, 5 * Q, 65535];
        uint256[8] memory counts = [uint256(0), 444, 445, 448, 509, 510, 511, 512];
        for (uint256 v; v < candidates.length; ++v) {
            bytes memory blockData = new bytes(160);
            for (uint256 j; j < 136; j += 2) {
                blockData[j] = bytes1(uint8(candidates[v] >> 8));
                blockData[j + 1] = bytes1(uint8(candidates[v]));
            }
            for (uint256 c; c < counts.length; ++c) {
                _check(product, blockData, counts[c], 34034725);
            }
        }
    }

    function _check(uint256[] memory product, bytes memory blockData, uint256 count, uint256 norm) internal pure {
        uint256 ptr;
        assembly ("memory-safe") {
            ptr := add(blockData, 32)
        }
        (uint256 actualCount, uint256 actualNorm) = _sampleShakeBlockNormPacked(product, count, ptr, norm);
        uint256[] memory wide = new uint256[](64);
        for (uint256 i; i < 512; ++i) {
            uint256 c = (product[i / 4] >> (64 * (i % 4))) & type(uint64).max;
            wide[i / 8] |= c << (32 * (i % 8));
        }
        (uint256 wideCount, uint256 wideNorm) = _sampleShakeBlockNormPacked8(wide, count, ptr, norm);
        assertEq(wideCount, actualCount, "eight-lane sample count");
        assertEq(wideNorm, actualNorm, "eight-lane sample norm");
        uint256[25] memory state;
        for (uint256 i; i < 17; ++i) {
            for (uint256 j; j < 8; ++j) {
                state[i] |= uint256(uint8(blockData[8 * i + j])) << (8 * j);
            }
        }
        // Capacity lanes must never contribute candidates to this rate block.
        for (uint256 i = 17; i < 25; ++i) {
            state[i] = type(uint64).max - i;
        }
        (uint256 stateCount, uint256 stateNorm) = _sampleShakeStateNormPacked8(wide, count, state, norm);
        assertEq(stateCount, actualCount, "direct-state sample count");
        assertEq(stateNorm, actualNorm, "direct-state sample norm");
        for (uint256 j; j < 136 && count < 512; j += 2) {
            uint256 t = (uint256(uint8(blockData[j])) << 8) | uint8(blockData[j + 1]);
            if (t >= 5 * Q) continue;
            uint256 coefficient = (product[count / 4] >> (64 * (count % 4))) & type(uint64).max;
            uint256 difference = addmod(t % Q, Q - coefficient % Q, Q);
            if (difference > Q / 2) difference = Q - difference;
            norm += difference * difference;
            ++count;
        }
        assertEq(actualCount, count, "sample count");
        assertEq(actualNorm, norm, "sample norm");
    }
}
