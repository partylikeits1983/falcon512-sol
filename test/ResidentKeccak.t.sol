// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

contract ResidentKeccakTest is Test {
    address private candidate;
    address private referenceHelper;

    function setUp() public {
        candidate = address(0x1601);
        referenceHelper = address(0x1600);
        string[] memory command = new string[](2);
        command[0] = "cat";
        command[1] = "test/fixtures/f1600_170.hex";
        vm.etch(referenceHelper, vm.ffi(command));
        command[1] = "test/fixtures/f1600_resident.hex";
        vm.etch(candidate, vm.ffi(command));
    }

    function testFuzz_Permutation(bytes32 seed) public view {
        uint256[25] memory state;
        for (uint256 i; i < 25; ++i) {
            state[i] = uint64(uint256(keccak256(abi.encode(seed, i))));
        }
        bytes memory input = abi.encode(state);
        (bool ok, bytes memory expected) = referenceHelper.staticcall(input);
        assertTrue(ok);
        (ok, input) = candidate.staticcall(input);
        assertTrue(ok);
        assertEq(input, expected);
        _checkResident(state, expected);
    }

    function _checkResident(uint256[25] memory state, bytes memory expected) internal view {
        uint256 replication = 1 + (uint256(1) << 64) + (uint256(1) << 128) + (uint256(1) << 192);
        for (uint256 i; i < 25; ++i) {
            state[i] *= replication;
        }
        (bool ok, bytes memory output) = candidate.staticcall(abi.encode(bytes32(type(uint256).max), state));
        assertTrue(ok);
        uint256[25] memory result = abi.decode(output, (uint256[25]));
        uint256[25] memory clean = abi.decode(expected, (uint256[25]));
        for (uint256 i; i < 25; ++i) {
            assertEq(result[i], clean[i] * replication, "replicated lane");
        }
    }

    function test_InvalidInputLengths() public view {
        uint256[6] memory sizes = [uint256(0), 799, 801, 831, 833, 1600];
        for (uint256 i; i < sizes.length; ++i) {
            (bool ok,) = candidate.staticcall(new bytes(sizes[i]));
            assertFalse(ok);
        }
    }

    function test_GasPermutation() public {
        bytes memory input = new bytes(800);
        (bool ok, bytes memory expected) = referenceHelper.staticcall(input);
        assertTrue(ok);
        emit log_named_uint("Reference permutation", vm.snapshotGasLastCall("reference"));
        (ok, input) = candidate.staticcall(new bytes(832));
        assertTrue(ok);
        emit log_named_uint("Candidate permutation", vm.snapshotGasLastCall("candidate"));
        uint256[25] memory state;
        _checkResident(state, expected);
    }
}
