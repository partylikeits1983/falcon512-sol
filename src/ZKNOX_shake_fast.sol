// SPDX-License-Identifier: MIT
// Portions Copyright (c) 2026 Fireblocks Ltd. - MIT
// from fireblocks-labs/evm-ml-dsa-verifier @ cca262b, src/FastKeccak170.sol
// FILE: ZKNOX_shake_fast.sol
//
// Drop-in replacement for the SHAKE256 XOF used by hashToPointNIST.
//
// The sponge glue (_xorBlockFast170 / _squeezeBlockFast170 / f1600Fast170) is
// taken verbatim from fireblocks-labs/evm-ml-dsa-verifier (MIT),
// src/FastKeccak170.sol. The Keccak-f[1600] permutation itself is NOT Solidity
// here: it is a 21,622-byte fully-unrolled raw-runtime helper contract
// (helpers/f1600_170.hex in that repository) reached by STATICCALL, with the
// 25-lane state passed in and out in place.
//
// hashToPointNISTFast below keeps the rejection sampler of
// ZKNOX_HashToPoint.hashToPointNIST byte for byte. Only the XOF changes.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

uint256 constant _M64_170 = 0xffffffffffffffff;
uint256 constant _RATE_FAST = 136;

error F1600CallFailed();

/// @notice Keccak-f[1600] permutation, in place on `st` (25 words, lane i = x + 5*y).
function f1600Fast170(uint256[25] memory st, address helper) view {
    bool ok;
    assembly ("memory-safe") {
        ok := staticcall(gas(), helper, st, 800, st, 800)
        ok := and(ok, eq(returndatasize(), 800))
    }
    if (!ok) revert F1600CallFailed();
}

/// @dev XOR one 136-byte rate block at memory `ptr` into the sponge state (lanes 0..16).
function _xorBlockFast170(uint256[25] memory st, uint256 ptr) pure {
    assembly ("memory-safe") {
        function grev(w) -> v {
            let a := and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)
            v := or(shr(8, a), shl(8, xor(w, a)))
            a := and(v, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)
            v := or(shr(16, a), shl(16, xor(v, a)))
            a := and(v, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)
            v := or(shr(32, a), shl(32, xor(v, a)))
        }
        let v := grev(mload(ptr))
        mstore(st, xor(mload(st), shr(192, v)))
        mstore(add(st, 32), xor(mload(add(st, 32)), and(shr(128, v), _M64_170)))
        mstore(add(st, 64), xor(mload(add(st, 64)), and(shr(64, v), _M64_170)))
        mstore(add(st, 96), xor(mload(add(st, 96)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 32)))
        mstore(add(st, 128), xor(mload(add(st, 128)), shr(192, v)))
        mstore(add(st, 160), xor(mload(add(st, 160)), and(shr(128, v), _M64_170)))
        mstore(add(st, 192), xor(mload(add(st, 192)), and(shr(64, v), _M64_170)))
        mstore(add(st, 224), xor(mload(add(st, 224)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 64)))
        mstore(add(st, 256), xor(mload(add(st, 256)), shr(192, v)))
        mstore(add(st, 288), xor(mload(add(st, 288)), and(shr(128, v), _M64_170)))
        mstore(add(st, 320), xor(mload(add(st, 320)), and(shr(64, v), _M64_170)))
        mstore(add(st, 352), xor(mload(add(st, 352)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 96)))
        mstore(add(st, 384), xor(mload(add(st, 384)), shr(192, v)))
        mstore(add(st, 416), xor(mload(add(st, 416)), and(shr(128, v), _M64_170)))
        mstore(add(st, 448), xor(mload(add(st, 448)), and(shr(64, v), _M64_170)))
        mstore(add(st, 480), xor(mload(add(st, 480)), and(v, _M64_170)))
        v := grev(mload(add(ptr, 104)))
        mstore(add(st, 512), xor(mload(add(st, 512)), and(v, _M64_170)))
    }
}

/// @dev Write one full 136-byte squeeze block from the state to memory at `outPtr`.
function _squeezeBlockFast170(uint256[25] memory st, uint256 outPtr) pure {
    assembly ("memory-safe") {
        function grev(w) -> v {
            v := or(
                and(shl(8, w), 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00),
                and(shr(8, w), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)
            )
            v := or(
                and(shl(16, v), 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000),
                and(shr(16, v), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)
            )
            v := or(
                and(shl(32, v), 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000),
                and(shr(32, v), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
            )
        }
        mstore(
            outPtr,
            grev(
                or(
                    or(or(shl(192, mload(st)), shl(128, mload(add(st, 32)))), shl(64, mload(add(st, 64)))),
                    mload(add(st, 96))
                )
            )
        )
        mstore(
            add(outPtr, 32),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 128))), shl(128, mload(add(st, 160)))), shl(64, mload(add(st, 192)))),
                    mload(add(st, 224))
                )
            )
        )
        mstore(
            add(outPtr, 64),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 256))), shl(128, mload(add(st, 288)))), shl(64, mload(add(st, 320)))),
                    mload(add(st, 352))
                )
            )
        )
        mstore(
            add(outPtr, 96),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 384))), shl(128, mload(add(st, 416)))), shl(64, mload(add(st, 448)))),
                    mload(add(st, 480))
                )
            )
        )
        mstore(
            add(outPtr, 104),
            grev(
                or(
                    or(or(shl(192, mload(add(st, 416))), shl(128, mload(add(st, 448)))), shl(64, mload(add(st, 480)))),
                    mload(add(st, 512))
                )
            )
        )
    }
}

/// @dev Absorb `input` with FIPS 202 1111 + pad10*1 padding and run the final permutation.
///      Leaves `st` ready for the first squeeze block.
function _absorbFast170(uint256[25] memory st, bytes memory input, address helper) view {
    uint256 ptr;
    uint256 len = input.length;
    assembly ("memory-safe") {
        ptr := add(input, 32)
    }
    unchecked {
        uint256 nFull = len / 136;
        for (uint256 i = 0; i < nFull; ++i) {
            _xorBlockFast170(st, ptr);
            f1600Fast170(st, helper);
            ptr += 136;
        }
        uint256 rem = len - nFull * 136;
        bytes memory last = new bytes(136);
        uint256 tail = nFull * 136;
        for (uint256 i = 0; i < rem; ++i) {
            last[i] = input[tail + i];
        }
        last[rem] = 0x1f;
        last[135] = bytes1(uint8(last[135]) ^ 0x80);
        assembly ("memory-safe") {
            ptr := add(last, 32)
        }
        _xorBlockFast170(st, ptr);
        f1600Fast170(st, helper);
    }
}

function _zeroRateBlock(uint256 ptr) pure {
    assembly ("memory-safe") {
        mstore(ptr, 0)
        mstore(add(ptr, 32), 0)
        mstore(add(ptr, 64), 0)
        mstore(add(ptr, 96), 0)
        mstore(add(ptr, 128), 0)
    }
}

function _allocRateBlock() pure returns (uint256 ptr) {
    assembly ("memory-safe") {
        ptr := mload(0x40)
        mstore(0x40, add(ptr, 192))
    }
}

function _absorbCalldataSegmentFast170(
    uint256[25] memory st,
    uint256 blockPtr,
    uint256 filled,
    uint256 src,
    uint256 len,
    address helper
) view returns (uint256) {
    unchecked {
        uint256 offset = 0;
        while (offset < len) {
            uint256 take = _RATE_FAST - filled;
            uint256 remaining = len - offset;
            if (take > remaining) take = remaining;
            assembly ("memory-safe") {
                calldatacopy(add(blockPtr, filled), add(src, offset), take)
            }
            filled += take;
            offset += take;
            if (filled == _RATE_FAST) {
                _xorBlockFast170(st, blockPtr);
                f1600Fast170(st, helper);
                _zeroRateBlock(blockPtr);
                filled = 0;
            }
        }
        return filled;
    }
}

function _absorbSaltMessageCalldataFast170(
    uint256[25] memory st,
    bytes calldata salt,
    bytes calldata msgHash,
    address helper
) view {
    if (salt.length == 40 && msgHash.length < 96) {
        uint256 shortPtr = _allocRateBlock();
        _zeroRateBlock(shortPtr);
        uint256 msgLen = msgHash.length;
        assembly ("memory-safe") {
            calldatacopy(shortPtr, salt.offset, 40)
            calldatacopy(add(shortPtr, 40), msgHash.offset, msgLen)
            let filled := add(40, msgLen)
            mstore8(add(shortPtr, filled), 0x1f)
            mstore8(add(shortPtr, 135), xor(byte(0, mload(add(shortPtr, 135))), 0x80))
        }
        _xorBlockFast170(st, shortPtr);
        f1600Fast170(st, helper);
        return;
    }

    uint256 blockPtr = _allocRateBlock();
    _zeroRateBlock(blockPtr);

    uint256 saltOffset;
    uint256 msgOffset;
    assembly ("memory-safe") {
        saltOffset := salt.offset
        msgOffset := msgHash.offset
    }

    uint256 filled = _absorbCalldataSegmentFast170(st, blockPtr, 0, saltOffset, salt.length, helper);
    filled = _absorbCalldataSegmentFast170(st, blockPtr, filled, msgOffset, msgHash.length, helper);

    assembly ("memory-safe") {
        mstore8(add(blockPtr, filled), 0x1f)
        mstore8(add(blockPtr, 135), xor(byte(0, mload(add(blockPtr, 135))), 0x80))
    }
    _xorBlockFast170(st, blockPtr);
    f1600Fast170(st, helper);
}

function _sampleShakeBlock(uint256[] memory hashed, uint256 count, uint256 outPtr) pure returns (uint256 nextCount) {
    assembly ("memory-safe") {
        let dst := add(add(hashed, 32), shl(5, count))
        let dstEnd := add(hashed, 16416)
        for { let j := 0 } and(lt(j, _RATE_FAST), lt(dst, dstEnd)) { j := add(j, 2) } {
            let t := shr(240, mload(add(outPtr, j)))
            if lt(t, kq) {
                mstore(dst, mod(t, q))
                dst := add(dst, 32)
            }
        }
        nextCount := shr(5, sub(dst, add(hashed, 32)))
    }
}

function _sampleShakeBlockNorm(uint256[] memory product, uint256 count, uint256 outPtr, uint256 norm)
    pure
    returns (uint256 nextCount, uint256 nextNorm)
{
    assembly ("memory-safe") {
        let productPtr := add(add(product, 32), shl(5, count))
        let productEnd := add(product, 16416)
        for { let j := 0 } and(lt(j, _RATE_FAST), lt(productPtr, productEnd)) { j := add(j, 2) } {
            let t := shr(240, mload(add(outPtr, j)))
            if lt(t, kq) {
                let s1i := addmod(mod(t, q), sub(q, mload(productPtr)), q)
                if gt(s1i, qs1) { s1i := sub(q, s1i) }
                norm := add(norm, mul(s1i, s1i))
                productPtr := add(productPtr, 32)
            }
        }
        nextCount := shr(5, sub(productPtr, add(product, 32)))
        nextNorm := norm
    }
}

function _sampleShakeBlockNormPacked(uint256[] memory product, uint256 count, uint256 outPtr, uint256 norm)
    pure
    returns (uint256 nextCount, uint256 nextNorm)
{
    assembly ("memory-safe") {
        let productBase := add(product, 32)
        let productPtr := add(productBase, shl(5, shr(2, count)))
        let productEnd := add(productBase, 4096)
        let laneShift := shl(6, and(count, 3))

        for { let j := 0 } and(lt(j, _RATE_FAST), lt(productPtr, productEnd)) { j := add(j, 2) } {
            let t := shr(240, mload(add(outPtr, j)))
            if lt(t, kq) {
                let productCoeff := mod(and(shr(laneShift, mload(productPtr)), _M64_170), q)
                let s1i := addmod(mod(t, q), sub(q, productCoeff), q)
                if gt(s1i, qs1) { s1i := sub(q, s1i) }
                norm := add(norm, mul(s1i, s1i))

                laneShift := add(laneShift, 64)
                if eq(laneShift, 256) {
                    productPtr := add(productPtr, 32)
                    laneShift := 0
                }
            }
        }

        nextCount := add(shr(3, sub(productPtr, productBase)), shr(6, laneShift))
        nextNorm := norm
    }
}

function _finishNormWithS2Calldata(uint256 norm, uint256[] calldata s2) pure returns (bool result) {
    uint256 outOfRange = 0;
    assembly ("memory-safe") {
        let aa := s2.offset
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let ai := calldataload(add(aa, shl(5, i)))
            for { let j := 0 } lt(j, 16) { j := add(j, 1) } {
                let s2i := and(shr(shl(4, j), ai), 0xffff)
                outOfRange := or(outOfRange, iszero(lt(s2i, q)))
                if gt(s2i, qs1) { s2i := sub(q, s2i) }
                norm := add(norm, mul(s2i, s2i))
            }
        }

        result := and(iszero(outOfRange), lt(norm, sigBound))
    }
}

/// @notice Minimal SHAKE256 over the external helper. Same contract as shake256().
function shake256Fast(bytes memory input, uint256 outLen, address helper) view returns (bytes memory output) {
    uint256[25] memory st;
    _absorbFast170(st, input, helper);
    unchecked {
        uint256 nOut = outLen == 0 ? 1 : (outLen + 135) / 136;
        output = new bytes(nOut * 136);
        uint256 outPtr;
        assembly ("memory-safe") {
            outPtr := add(output, 32)
            mstore(output, outLen)
        }
        uint256 done = 0;
        while (true) {
            _squeezeBlockFast170(st, outPtr + done);
            done += 136;
            if (done >= outLen) break;
            f1600Fast170(st, helper);
        }
    }
}

/// @notice hashToPointNIST with the pure-Solidity SHAKE replaced by the helper-backed one.
/// @dev The rejection sampler is IDENTICAL to ZKNOX_HashToPoint.hashToPointNIST:
///      same big-endian 16-bit reads out of a `bytes memory` rate block, same
///      `< kq` acceptance, same `% q`. Only the XOF underneath changes, so the
///      delta is the SHAKE cost and nothing else.
function hashToPointNISTFast(bytes memory salt, bytes memory msgHash, address helper) view returns (uint256[] memory) {
    // SALT AND MSG ARE SWAPPED! (kept from the original)
    uint256[] memory hashed = new uint256[](512);
    uint256 i = 0;

    uint256[25] memory st;
    _absorbFast170(st, abi.encodePacked(salt, msgHash), helper);

    uint256 outPtr = _allocRateBlock();
    unchecked {
        while (i < n) {
            _squeezeBlockFast170(st, outPtr);
            i = _sampleShakeBlock(hashed, i, outPtr);
            if (i == n) break;
            f1600Fast170(st, helper);
        }
    }
    return hashed;
}

function hashToPointNISTFastCalldata(bytes calldata salt, bytes calldata msgHash, address helper)
    view
    returns (uint256[] memory)
{
    uint256[] memory hashed = new uint256[](512);
    uint256 i = 0;

    uint256[25] memory st;
    _absorbSaltMessageCalldataFast170(st, salt, msgHash, helper);

    uint256 outPtr = _allocRateBlock();
    unchecked {
        while (i < n) {
            _squeezeBlockFast170(st, outPtr);
            i = _sampleShakeBlock(hashed, i, outPtr);
            if (i == n) break;
            f1600Fast170(st, helper);
        }
    }
    return hashed;
}

function verifyWithHashToPointNISTFastCalldata(
    bytes calldata salt,
    bytes calldata msgHash,
    address helper,
    uint256[] memory product,
    uint256[] calldata s2
) view returns (bool) {
    if (product.length != 512 || s2.length != falcon_S256) return false;

    uint256 count = 0;
    uint256 norm = 0;

    uint256[25] memory st;
    _absorbSaltMessageCalldataFast170(st, salt, msgHash, helper);

    uint256 outPtr = _allocRateBlock();

    unchecked {
        while (count < n) {
            _squeezeBlockFast170(st, outPtr);
            (count, norm) = _sampleShakeBlockNorm(product, count, outPtr, norm);
            if (count == n) break;
            f1600Fast170(st, helper);
        }
    }

    return _finishNormWithS2Calldata(norm, s2);
}

function verifyWithHashToPointNISTFastCalldataPackedProduct(
    bytes calldata salt,
    bytes calldata msgHash,
    address helper,
    uint256[] memory product,
    uint256 norm
) view returns (bool) {
    uint256 count = 0;

    uint256[25] memory st;
    _absorbSaltMessageCalldataFast170(st, salt, msgHash, helper);

    uint256 outPtr = _allocRateBlock();

    unchecked {
        while (count < n) {
            _squeezeBlockFast170(st, outPtr);
            (count, norm) = _sampleShakeBlockNormPacked(product, count, outPtr, norm);
            if (count == n) break;
            f1600Fast170(st, helper);
        }
    }

    return norm < sigBound;
}
