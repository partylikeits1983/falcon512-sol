// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";
import {compactPolynomial} from "../src/FalconUtils.sol";
import {_nttFwPacked, _nttInvPacked, _packFromCompact, _unpackTo512, _vecMulPacked} from "../src/FalconNTT.sol";
import {falcon_product_packed_words_calldata_with_s2_norm} from "../src/FalconProduct.sol";

contract ProductHarness {
    function product(uint256[] calldata a, uint256[] calldata key)
        external
        pure
        returns (uint256[] memory, uint256, uint256)
    {
        return falcon_product_packed_words_calldata_with_s2_norm(a, key);
    }
}

contract PackedArithmeticTest is Test {
    uint256 private constant Q = 12289;

    function test_GasPolynomialStages() public {
        uint256[] memory compact = new uint256[](32);
        uint256 before = gasleft();
        uint256[] memory a = _packFromCompact(compact);
        emit log_named_uint("Pack", before - gasleft());
        before = gasleft();
        a = _nttFwPacked(a);
        emit log_named_uint("Forward NTT", before - gasleft());
        uint256[] memory key = _packFromCompact(compact);
        before = gasleft();
        a = _vecMulPacked(a, key);
        emit log_named_uint("Memory pointwise product", before - gasleft());
        before = gasleft();
        a = _nttInvPacked(a);
        emit log_named_uint("Inverse NTT", before - gasleft());
        assertEq(_unpackTo512(a)[0], 0);
    }

    function testFuzz_CalldataProductAndNorm(bytes32 seed) public {
        uint256[] memory a = new uint256[](512);
        uint256[] memory key = new uint256[](512);
        uint256 expectedNorm;
        for (uint256 i; i < 512; ++i) {
            uint256 value = uint256(keccak256(abi.encode(seed, i)));
            uint256 magnitude = value % 101;
            a[i] = value & 256 == 0 || magnitude == 0 ? magnitude : Q - magnitude;
            expectedNorm += magnitude * magnitude;
            key[i] = (value >> 32) & 0xffff;
        }
        uint256[] memory compact = compactPolynomial(a);
        uint256[] memory compactKey = compactPolynomial(key);
        (uint256[] memory actual, uint256 norm, uint256 invalid) = new ProductHarness().product(compact, compactKey);
        uint256[] memory expected = _unpackTo512(
            _nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompact(compact)), _packFromCompact(compactKey)))
        );
        assertEq(_unpackTo512(actual), expected, "calldata product");
        assertEq(norm, expectedNorm, "centered norm");
        assertEq(invalid, 0);
    }

    function test_RejectInvalidCoefficientsAndExcessiveNorm() public {
        ProductHarness harness = new ProductHarness();
        uint256[] memory compact = new uint256[](32);
        uint256[] memory key = new uint256[](32);
        for (uint256 lane; lane < 16; ++lane) {
            compact[0] = Q << (16 * lane);
            (,, uint256 invalid) = harness.product(compact, key);
            assertTrue(invalid != 0);
            compact[0] = uint256(65535) << (16 * lane);
            (,, invalid) = harness.product(compact, key);
            assertTrue(invalid != 0);
        }
        compact[0] = 6144;
        (,, uint256 excessive) = harness.product(compact, key);
        assertTrue(excessive != 0);
    }

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
        uint256[] memory compact = compactPolynomial(a);
        uint256[] memory transformed = _nttFwPacked(_packFromCompact(compact));
        assertEq(_unpackTo512(_nttInvPacked(_packTransformed(transformed))), a, "round trip");
        assertEq(_unpackTo512(transformed), _forward(a), "scalar forward");
    }

    function _packTransformed(uint256[] memory a) internal pure returns (uint256[] memory b) {
        // Canonicalize before inverse, as the pointwise multiplication does.
        b = _packFromCompact(compactPolynomial(_unpackTo512(a)));
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
                    _nttFwPacked(_packFromCompact(compactPolynomial(a))),
                    _nttFwPacked(_packFromCompact(compactPolynomial(b)))
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
