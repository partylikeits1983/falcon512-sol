// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

// Portions: Apache-2.0

////////////////////////////////////////////////////////////////////////////////
// Algorithm and code from OQS and PQClean projects.
//     * OQS: https://github.com/open-quantum-safe/
//     * PQClean: https://github.com/PQClean/
//
// Solidity port by Cambridge Quantum Computing Ltd for IDB Lacchain project
//     * https://github.com/lacchain/
//     * https://www.cambridgequantum.com
// JGilmore (22/02/2021 12:37)
////////////////////////////////////////////////////////////////////////////////

interface IFalcon512Tables {
    function gmb() external view returns (bytes memory);
    function igmb() external view returns (bytes memory);
}

contract Falcon {
    IFalcon512Tables private immutable tables;

    constructor(address tables_) {
        tables = IFalcon512Tables(tables_);
    }
    // ***************************************************************************
    // ** CONSTANTS
    // ***************************************************************************

    int16 private constant FALCON_ERR_SUCCESS = 0;
    int16 private constant FALCON_ERR_BADSIG = -4;
    int16 private constant FALCON_ERR_UNDEFINED = -99;

    uint32 private constant SHAKE256_RATE = 136;
    uint256 private constant KECCAK_ROTATIONS = 0x00000000000000002c143d27123e2b190838291b0e02372d241c150f0a060301;
    uint256 private constant KECCAK_PI_INDEXES = 0x0000000000000000010609160e14020c0d13170f0418150810050312110b070a;
    uint256 private constant KECCAK_RC_0 = 0x8000000080008000800000000000808a00000000000080820000000000000001;
    uint256 private constant KECCAK_RC_1 = 0x800000000000800980000000800080810000000080000001000000000000808b;
    uint256 private constant KECCAK_RC_2 = 0x000000008000000a00000000800080090000000000000088000000000000008a;
    uint256 private constant KECCAK_RC_3 = 0x80000000000080038000000000008089800000000000008b000000008000808b;
    uint256 private constant KECCAK_RC_4 = 0x800000008000000a000000000000800a80000000000000808000000000008002;
    uint256 private constant KECCAK_RC_5 = 0x8000000080008008000000008000000180000000000080808000000080008081;

    // From: pqclean.c
    uint16 private constant PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES = 897;
    uint16 private constant NONCELEN = 40;

    // From: vrfy_constants.h
    uint32 private constant Q = 12289;
    uint32 private constant Q0I = 12287;
    uint32 private constant R = 4091;
    uint32 private constant R2 = 10952;

    // ***************************************************************************
    // ** IMPLEMENTATION: Utility functions
    // ***************************************************************************

    // ==== vrfy.c BEGIN =====================================================================================================================

    //////////////////////////////////////////////////////////////////
    // Functions that do arithmetic on scalars
    //////////////////////////////////////////////////////////////////

    ////////////////////////////////////////
    // Addition modulo q. Operands must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_add(uint32 x, uint32 y) private pure returns (uint32 result) {
        uint32 d;

        d = x + y - Q;
        d += Q & -(d >> 31);
        result = d;
    }

    ////////////////////////////////////////
    // Subtraction modulo q. Operands must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_sub(uint32 x, uint32 y) private pure returns (uint32 result) {
        // As in mq_add(), we use a conditional addition to ensure the result is in the 0..q-1 range.
        uint32 d;

        d = x - y;
        d += Q & -(d >> 31);
        return d;
    }

    ////////////////////////////////////////
    // Montgomery multiplication modulo q. If we set R = 2^16 mod q, then this function computes: x * y / R mod q
    // Operands must be in the 0..q-1 range.
    ////////////////////////////////////////
    function mq_montymul(uint32 x, uint32 y) private pure returns (uint32 result) {
        uint32 z;
        uint32 w;

        z = x * y;
        w = ((z * Q0I) & 0xFFFF) * Q;
        z = (z + w) >> 16;
        z -= Q;
        z += Q & -(z >> 31);
        return z;
    }

    ////////////////////////////////////////
    // Compute NTT on a ring element.
    // JG: Number-theoretic transform
    ////////////////////////////////////////
    function mq_NTT(uint16[] memory pWordArray, bytes memory gmbTable) private pure {
        uint32 t = 512;
        for (uint32 m = 1; m < 512; m <<= 1) {
            uint32 ht = t >> 1;
            uint32 j1 = 0;
            for (uint32 i = 0; i < m; i++) {
                uint32 s = tableValue(gmbTable, m + i);
                uint32 j2 = j1 + ht;
                for (uint32 j = j1; j < j2; j++) {
                    uint32 u = pWordArray[j];
                    uint32 v = mq_montymul(pWordArray[j + ht], s);
                    pWordArray[j] = uint16(mq_add(u, v));
                    pWordArray[j + ht] = uint16(mq_sub(u, v));
                }
                j1 += t;
            }

            t = ht;
        }
    }

    ////////////////////////////////////////
    // Compute the inverse NTT on a ring element, binary case.
    ////////////////////////////////////////
    function mq_iNTT(uint16[] memory pWordArray, bytes memory igmbTable) private pure {
        uint32 t = 1;
        uint32 m = 512;
        while (m > 1) {
            uint32 hm = m >> 1;
            uint32 dt = t << 1;
            uint32 j1 = 0;
            for (uint32 i = 0; i < hm; i++) {
                uint32 s = tableValue(igmbTable, hm + i);
                for (uint32 j = j1; j < j1 + t; j++) {
                    uint32 u = pWordArray[j];
                    uint32 v = pWordArray[j + t];
                    pWordArray[j] = uint16(mq_add(u, v));
                    pWordArray[j + t] = uint16(mq_montymul(mq_sub(u, v), s));
                }
                j1 += dt;
            }

            t = dt;
            m = hm;
        }

        uint32 ni = 128;
        for (m = 0; m < 512; m++) {
            pWordArray[m] = uint16(mq_montymul(pWordArray[m], ni));
        }
    }

    ////////////////////////////////////////
    // Convert a polynomial (mod q) to Montgomery representation.
    ////////////////////////////////////////
    function mq_poly_tomonty(uint16[] memory pWordArrayF) private pure {
        uint32 u;

        for (u = 0; u < 512; u++) {
            pWordArrayF[u] = uint16(mq_montymul(pWordArrayF[u], R2));
        }
    }

    ////////////////////////////////////////
    // Multiply two polynomials together (NTT representation, and using
    // a Montgomery multiplication). Result f*g is written over f.
    ////////////////////////////////////////
    function mq_poly_montymul_ntt(uint16[] memory pWordArrayF, uint16[] memory pWordArrayG) private pure {
        uint32 u;

        for (u = 0; u < 512; u++) {
            pWordArrayF[u] = uint16(mq_montymul(pWordArrayF[u], pWordArrayG[u]));
        }
    }

    ////////////////////////////////////////
    // Subtract polynomial g from polynomial f.
    ////////////////////////////////////////
    function mq_poly_sub(uint16[] memory pWordArrayF, uint16[] memory pWordArrayG) private pure {
        uint32 u;

        for (u = 0; u < 512; u++) {
            pWordArrayF[u] = uint16(mq_sub(pWordArrayF[u], pWordArrayG[u]));
        }
    }

    /* ===================================================================== */

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_to_ntt_monty(uint16[] memory pWordArrayH) private view {
        mq_NTT(pWordArrayH, tables.gmb());
        mq_poly_tomonty(pWordArrayH);
    }

    function tableValue(bytes memory table, uint32 index) private pure returns (uint32) {
        uint32 offset = index * 2;
        uint256 value;
        assembly {
            value := shr(240, mload(add(add(table, 0x20), offset)))
        }
        return uint32(value);
    }

    function hash_to_point_rust(uint16[] memory output, bytes calldata signature, bytes calldata message)
        private
        pure
    {
        uint64[25] memory state;
        uint32 absorbOffset = 0;
        absorbOffset = shake256_absorb_calldata(state, absorbOffset, signature, 1, NONCELEN);
        absorbOffset = shake256_absorb_calldata(state, absorbOffset, message, 0, uint32(message.length));
        shake256_finalize(state, absorbOffset);

        uint32 available = 0;
        uint32 u = 0;
        while (u < 512) {
            uint8 b0;
            uint8 b1;
            (b0, available) = shake256_squeeze_byte(state, available);
            (b1, available) = shake256_squeeze_byte(state, available);

            uint32 t = (uint32(b0) << 8) | uint32(b1);
            if (t < 61445) {
                output[u++] = uint16(t % Q);
            }
        }
    }

    function shake256_absorb_calldata(
        uint64[25] memory state,
        uint32 offset,
        bytes calldata input,
        uint32 inputOffset,
        uint32 inputLen
    ) private pure returns (uint32) {
        for (uint32 i = 0; i < inputLen; i++) {
            state[offset >> 3] ^= uint64(uint8(input[inputOffset + i])) << (8 * (offset & 7));
            offset++;
            if (offset == SHAKE256_RATE) {
                keccak_f1600(state);
                offset = 0;
            }
        }
        return offset;
    }

    function shake256_finalize(uint64[25] memory state, uint32 offset) private pure {
        state[offset >> 3] ^= uint64(0x1F) << (8 * (offset & 7));
        state[(SHAKE256_RATE - 1) >> 3] ^= uint64(0x80) << (8 * ((SHAKE256_RATE - 1) & 7));
    }

    function shake256_squeeze_byte(uint64[25] memory state, uint32 available)
        private
        pure
        returns (uint8 out, uint32 nextAvailable)
    {
        if (available == 0) {
            keccak_f1600(state);
            available = SHAKE256_RATE;
        }

        uint32 offset = SHAKE256_RATE - available;
        out = uint8(state[offset >> 3] >> (8 * (offset & 7)));
        nextAvailable = available - 1;
    }

    function keccak_f1600(uint64[25] memory state) private pure {
        uint64[5] memory bc;
        for (uint256 round = 0; round < 24; round++) {
            for (uint256 i = 0; i < 5; i++) {
                bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }
            for (uint256 i = 0; i < 5; i++) {
                uint64 x = bc[(i + 1) % 5];
                uint64 d = bc[(i + 4) % 5] ^ ((x << 1) ^ (x >> 63));
                for (uint256 j = 0; j < 25; j += 5) {
                    state[j + i] ^= d;
                }
            }

            uint64 current = state[1];
            for (uint256 i = 0; i < 24; i++) {
                uint8 j = keccak_pi(i);
                uint16 rot = keccak_rot(i);
                uint64 temp = state[j];
                state[j] = (current << rot) ^ (current >> (64 - rot));
                current = temp;
            }

            for (uint256 j = 0; j < 25; j += 5) {
                for (uint256 i = 0; i < 5; i++) {
                    bc[i] = state[j + i];
                }
                for (uint256 i = 0; i < 5; i++) {
                    state[j + i] = bc[i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5]);
                }
            }

            state[0] ^= keccak_round_constant(round);
        }
    }

    function keccak_round_constant(uint256 round) private pure returns (uint64) {
        uint256 packed;
        if (round < 4) {
            packed = KECCAK_RC_0;
        } else if (round < 8) {
            packed = KECCAK_RC_1;
        } else if (round < 12) {
            packed = KECCAK_RC_2;
        } else if (round < 16) {
            packed = KECCAK_RC_3;
        } else if (round < 20) {
            packed = KECCAK_RC_4;
        } else {
            packed = KECCAK_RC_5;
        }
        return uint64((packed >> ((round & 3) * 64)) & 0xFFFFFFFFFFFFFFFF);
    }

    function keccak_rot(uint256 i) private pure returns (uint16) {
        return uint16((KECCAK_ROTATIONS >> (i * 8)) & 0xFF);
    }

    function keccak_pi(uint256 i) private pure returns (uint8) {
        return uint8((KECCAK_PI_INDEXES >> (i * 8)) & 0xFF);
    }

    function PQCLEAN_FALCON512_CLEAN_is_short(uint16[] memory s1, int16[] memory s2) private pure returns (int16) {
        uint32 s = 0;
        uint32 ng = 0;
        for (uint32 u = 0; u < 512; u++) {
            s += squareInt16(int16(s1[u]));
            ng |= s;

            s += squareInt16(s2[u]);
            ng |= s;
        }

        s |= -(ng >> 31);

        if (s < 34034726) {
            return 1;
        }
        return 0;
    }

    function squareInt16(int16 x) private pure returns (uint32) {
        int32 y = int32(x);
        return uint32(y * y);
    }

    // ==== common.c END =====================================================================================================================

    // ==== codec.c BEGIN =====================================================================================================================

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_modq_decode(
        uint16[] memory pX,
        bytes calldata pInput,
        uint16 In_offset,
        uint16 cbInputMax
    ) private pure returns (uint16) {
        uint16 In_len = 896;
        uint16 u;
        uint16 buf_ndx;
        uint32 acc;
        uint16 acc_len;

        if (In_len > cbInputMax) {
            return 0;
        }

        buf_ndx = 0;
        acc = 0;
        acc_len = 0;
        u = 0;

        while (u < 512) {
            acc = (acc << 8) | uint32(uint8(pInput[In_offset + buf_ndx++]));
            acc_len += 8;
            if (acc_len >= 14) {
                uint16 w;

                acc_len -= 14;
                w = uint16((acc >> acc_len) & 0x3FFF);
                if (w >= 12289) {
                    w -= uint16(Q);
                }
                pX[u++] = uint16(w);
            }
        }

        if ((acc & ((uint32(1) << acc_len) - 1)) != 0) {
            return 0;
        }

        return In_len;
    }

    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_comp_decode(
        int16[] memory pOutput,
        bytes calldata pInput,
        uint16 In_offset,
        uint16 cbInputMax
    ) private pure returns (uint16) {
        uint32 bitIndex = 0;
        uint32 bitLen = uint32(cbInputMax) * 8;

        for (uint16 u = 0; u < 512; u++) {
            if (bitIndex + 8 > bitLen) {
                return 0;
            }

            uint16 b = getSignatureByte(pInput, In_offset, bitIndex);
            bitIndex += 8;
            uint16 s = b & 128;
            uint16 m = b & 127;

            for (;;) {
                if (bitIndex >= bitLen) {
                    return 0;
                }
                uint16 bit = getSignatureBit(pInput, In_offset, bitIndex);
                bitIndex++;
                if (bit != 0) {
                    break;
                }

                m += 128;
                if (m > 2047) {
                    return 0;
                }
            }

            if (s != 0 && m == 0) {
                return 0;
            }
            pOutput[u] = int16((s != 0) ? -int256(m) : int256(m));
        }

        while (bitIndex < bitLen) {
            if (getSignatureBit(pInput, In_offset, bitIndex) != 0) {
                return 0;
            }
            bitIndex++;
        }
        return cbInputMax;
    }

    function getSignatureBit(bytes calldata pInput, uint16 In_offset, uint32 bitIndex) private pure returns (uint16) {
        return (uint16(uint8(pInput[uint32(In_offset) + (bitIndex >> 3)])) >> (7 - (bitIndex & 7))) & 1;
    }

    function getSignatureByte(bytes calldata pInput, uint16 In_offset, uint32 bitIndex) private pure returns (uint16) {
        uint32 byteIndex = uint32(In_offset) + (bitIndex >> 3);
        uint32 shift = bitIndex & 7;
        uint16 word = uint16(uint8(pInput[byteIndex])) << 8;
        if (shift != 0) {
            word |= uint16(uint8(pInput[byteIndex + 1]));
        }
        return (word >> (8 - shift)) & 0xFF;
    }

    // ==== codec.c END =====================================================================================================================

    // ==== vrfy.c BEGIN =====================================================================================================================
    ////////////////////////////////////////
    //
    ////////////////////////////////////////
    function PQCLEAN_FALCON512_CLEAN_verify_raw(
        uint16[] memory c0,
        int16[] memory s2,
        uint16[] memory pH,
        uint16[] memory pWorkingStorageWords
    ) private view returns (int16 result) {
        uint32 u;

        // Reduce s2 elements modulo q ([0..q-1] range).
        for (u = 0; u < 512; u++) {
            uint32 w;

            w = uint32(s2[u]);

            w += Q & -(w >> 31);
            pWorkingStorageWords[u] = uint16(w);
        }

        // Compute -s1 = s2*h - c0 mod phi mod q (in pWorkingStorageWords[]).
        mq_NTT(pWorkingStorageWords, tables.gmb());
        mq_poly_montymul_ntt(pWorkingStorageWords, pH);
        mq_iNTT(pWorkingStorageWords, tables.igmb());
        mq_poly_sub(pWorkingStorageWords, c0);

        // Normalize -s1 elements into the [-q/2..q/2] range.
        for (u = 0; u < 512; u++) {
            int32 w;

            w = int32(pWorkingStorageWords[u]);
            w -= int32(Q & -(((Q >> 1) - uint32(w)) >> 31));
            pWorkingStorageWords[u] = uint16(int16(w));
        }

        // Signature is valid if and only if the aggregate (-s1,s2) vector is short enough.
        int16 success = PQCLEAN_FALCON512_CLEAN_is_short(pWorkingStorageWords, s2);

        return success;
    }

    // ==== vrfy.c END =====================================================================================================================

    // ==== pqclean.c BEGIN =====================================================================================================================

    ////////////////////////////////////////
    //
    // int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t*  pSignatureBuf,
    //                                                size_t          cbSignatureBuf,
    //                                                const uint8_t*  pMessage,
    //                                                size_t          cbMessage,
    //                                                const uint8_t*  pPublicKey)
    ////////////////////////////////////////
    function verifyLegacy(bytes calldata pSignatureBuf, bytes calldata pMessage, bytes calldata pPublicKey)
        internal
        view
        returns (int16)
    {
        ////////////////////////////////////////////////
        // Start of Verification Proper
        ////////////////////////////////////////////////

        uint16[] memory pWordArrayH;
        int16[] memory pSignedWordArraySig;

        pWordArrayH = new uint16[](512);
        pSignedWordArraySig = new int16[](512);

        int16 rc = FALCON_ERR_UNDEFINED;

        {
            uint16 cbSignatureProper = 625;

            ////////////////////////////////////////
            // static int do_verify(const uint8_t*  pNonce,
            //                      const uint8_t*  pSignatureProper,
            //                      size_t          cbSignatureProper,
            //                      const uint8_t*  pMessage,
            //                      size_t          cbMessage,
            //                      const uint8_t*  pPublicKey)
            ////////////////////////////////////////

            uint16 sz1;
            uint16 sz2;

            ///////////////////////////////////////////////
            // Decode public key.
            sz1 = PQCLEAN_FALCON512_CLEAN_modq_decode(
                pWordArrayH, pPublicKey, 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1
            );
            if (sz1 != PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
                if (rc == FALCON_ERR_UNDEFINED) {
                    rc = FALCON_ERR_BADSIG + (-130);
                }
                return rc;
            }
            // JG: pWordArrayH now contains decoded public key
            PQCLEAN_FALCON512_CLEAN_to_ntt_monty(pWordArrayH);
            // JG: pWordArrayH now contains montified decoded public key

            ///////////////////////////////////////////////
            // Decode signature.
            sz2 =
                PQCLEAN_FALCON512_CLEAN_comp_decode(pSignedWordArraySig, pSignatureBuf, 1 + NONCELEN, cbSignatureProper);
            if (sz2 != cbSignatureProper) {
                if (rc == FALCON_ERR_UNDEFINED) {
                    rc = FALCON_ERR_BADSIG + (-140);
                }
                return rc;
            }
        }
        // JG: pSignedWordArraySig now contains the decoded signature

        uint16[] memory pWordArrayWorkingStorage;
        uint16[] memory pWordArrayHm;

        pWordArrayWorkingStorage = new uint16[](512);
        pWordArrayHm = new uint16[](512);

        ///////////////////////////////////////////////
        // Hash Nonce + Message into a vector.
        hash_to_point_rust(pWordArrayHm, pSignatureBuf, pMessage);

        // RULE: Signature Validation should succeed if all fields are valid

        ///////////////////////////////////////////////
        // Verify signature.
        int16 success =
            PQCLEAN_FALCON512_CLEAN_verify_raw(pWordArrayHm, pSignedWordArraySig, pWordArrayH, pWordArrayWorkingStorage);
        if (success == 0) {
            if (rc == FALCON_ERR_UNDEFINED) {
                rc = FALCON_ERR_BADSIG + (-150);
            }
            return rc;
        }

        if (rc == FALCON_ERR_UNDEFINED) {
            rc = FALCON_ERR_SUCCESS;
        }

        return rc;
    }

    // ==== pqclean.c END =====================================================================================================================
} // End of Contract
