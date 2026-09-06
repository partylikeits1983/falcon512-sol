// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {_ZKNOX_NTT_Compact} from "../src/ZKNOX_falcon_utils.sol";
import {
    _nttFwPacked,
    _nttInvPacked,
    _packFromCompact,
    _unpackTo512,
    _vecMulPacked
} from "../src/ZKNOX_NTT_falcon_packed.sol";

contract PackedArithmeticTest is Test {
    uint256 private constant Q = 12289;

    // Scalar modular arithmetic and independently computed powers of the
    // primitive 1024th root 49, without the production twiddle tables or SWAR.
    function _forward(uint256[] memory a) internal pure returns (uint256[] memory) {
        uint256 t = 512;
        for (uint256 m = 1; m < 512; m <<= 1) {
            t >>= 1;
            for (uint256 i; i < m; ++i) {
                uint256 index = m + i;
                uint256 reverse;
                for (uint256 b; b < 9; ++b) {
                    reverse = (reverse << 1) | (index & 1);
                    index >>= 1;
                }
                uint256 s = 1;
                uint256 root = 49;
                while (reverse != 0) {
                    if (reverse & 1 != 0) s = mulmod(s, root, Q);
                    root = mulmod(root, root, Q);
                    reverse >>= 1;
                }
                for (uint256 j = i * 2 * t; j < i * 2 * t + t; ++j) {
                    uint256 u = a[j];
                    uint256 v = mulmod(a[j + t], s, Q);
                    a[j] = addmod(u, v, Q);
                    a[j + t] = addmod(u, Q - v, Q);
                }
            }
        }
        return a;
    }

    function testFuzz_ForwardAndRoundTrip(bytes32 seed) public pure {
        uint256[] memory a = new uint256[](512);
        for (uint256 i; i < 512; ++i) {
            a[i] = uint256(keccak256(abi.encode(seed, i))) % Q;
        }
        _check(a);
    }

    function test_ArithmeticExtremes() public pure {
        uint256[] memory a = new uint256[](512);
        _check(a);
        for (uint256 i; i < 512; ++i) {
            a[i] = Q - 1;
        }
        _check(a);
        for (uint256 i; i < 512; ++i) {
            a[i] = i % 2 == 0 ? 0 : Q - 1;
        }
        _check(a);
    }

    function _check(uint256[] memory a) internal pure {
        uint256[] memory compact = _ZKNOX_NTT_Compact(a);
        uint256[] memory transformed = _nttFwPacked(_packFromCompact(compact));
        assertEq(_unpackTo512(_nttInvPacked(_packTransformed(transformed))), a, "round trip");
        assertEq(_unpackTo512(transformed), _forward(a), "scalar forward");
    }

    function _packTransformed(uint256[] memory a) internal pure returns (uint256[] memory b) {
        // Canonicalize before inverse, as the pointwise multiplication does.
        b = _packFromCompact(_ZKNOX_NTT_Compact(_unpackTo512(a)));
    }

    function testFuzz_ProductAgainstSchoolbook(bytes32 seed, uint16 index) public pure {
        uint256[] memory a = new uint256[](512);
        uint256[] memory b = new uint256[](512);
        for (uint256 i; i < 512; ++i) {
            a[i] = uint256(keccak256(abi.encode(seed, i, uint256(0)))) % Q;
            b[i] = uint256(keccak256(abi.encode(seed, i, uint256(1)))) % Q;
        }
        uint256[] memory actual = _unpackTo512(
            _nttInvPacked(
                _vecMulPacked(
                    _nttFwPacked(_packFromCompact(_ZKNOX_NTT_Compact(a))),
                    _nttFwPacked(_packFromCompact(_ZKNOX_NTT_Compact(b)))
                )
            )
        );
        // Four independently chosen coefficients of the negacyclic product.
        for (uint256 k; k < 4; ++k) {
            uint256 c = (uint256(index) + 127 * k) % 512;
            uint256 expected;
            for (uint256 i; i < 512; ++i) {
                uint256 term = mulmod(a[i], b[(512 + c - i) % 512], Q);
                expected = addmod(expected, i > c ? Q - term : term, Q);
            }
            assertEq(actual[c], expected, "schoolbook product");
        }
    }
}
