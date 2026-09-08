// SPDX-License-Identifier: MIT
// FILE: ZKNOX_NTT_falcon_packed.sol
//
// Packed-SWAR forward NTT for Falcon-512 (q = 12289, n = 512).
//
// Layout: 128 words of four 64-bit lanes; coefficient 4w+j sits in lane j of
// word w. q is 14 bits, so a 64-bit lane leaves 50 bits of headroom: sums stay
// UNREDUCED across all nine layers and only the twiddle multiply is reduced,
// with one Barrett step.
//
// Growth: Barrett leaves a residue < 2q (max 12316 measured, = 1.001q), the
// subtract branch adds a packed 4q bias to stay non-negative per lane, so the
// per-layer bound grows by 4q. Nine layers from q gives 37q = 454,693 < 2^19.
// The twiddle product is then < 2^19 * 2^14 = 2^33, and the Barrett multiply
// < 2^33 * M40 = 2^59.4, both inside a 64-bit lane. No lane ever carries into
// its neighbour.
//
// Layers t = 256..4 are word-aligned (t/4 >= 1 whole words), so one scalar
// multiply drives four butterflies. Layers t = 2 and t = 1 fall inside a word:
// t = 2 still shares one twiddle across the word, t = 1 needs two.
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";

uint256 constant _M40 = 89471204; // floor(2^40 / q)
uint256 constant _MASK24L = 0x0000000000ffffff0000000000ffffff0000000000ffffff0000000000ffffff;
uint256 constant _BIG4Q = 0x000000000000c004000000000000c004000000000000c004000000000000c004;
uint256 constant _LANE = 0xffffffffffffffff;
uint256 constant _L01 = 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff;
uint256 constant _L0 = 0x000000000000000000000000000000000000000000000000ffffffffffffffff;

/// @notice 32 compact words (16 x 16-bit) -> 128 packed words (4 x 64-bit lanes).
function _packFromCompact(uint256[] memory c) pure returns (uint256[] memory A) {
    A = new uint256[](128);
    assembly ("memory-safe") {
        let src := add(c, 32)
        let dst := add(A, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let ci := mload(add(src, shl(5, i)))
            let base := add(dst, shl(7, i)) // 4 words per source word
            // source word i holds coefficients 16i .. 16i+15, four per dest word
            for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                let s := shl(6, k) // 64 bits of source consumed per dest word
                let v := shr(s, ci)
                mstore(
                    add(base, shl(5, k)),
                    or(
                        or(and(v, 0xffff), shl(64, and(shr(16, v), 0xffff))),
                        or(shl(128, and(shr(32, v), 0xffff)), shl(192, and(shr(48, v), 0xffff)))
                    )
                )
            }
        }
    }
}

/// @notice Calldata variant of _packFromCompact, avoiding a dynamic-array memory copy.
function _packFromCompactCalldata(uint256[] calldata c) pure returns (uint256[] memory A) {
    A = new uint256[](128);
    assembly ("memory-safe") {
        let src := c.offset
        let dst := add(A, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let ci := calldataload(add(src, shl(5, i)))
            let base := add(dst, shl(7, i))
            for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                let s := shl(6, k)
                let v := shr(s, ci)
                mstore(
                    add(base, shl(5, k)),
                    or(
                        or(and(v, 0xffff), shl(64, and(shr(16, v), 0xffff))),
                        or(shl(128, and(shr(32, v), 0xffff)), shl(192, and(shr(48, v), 0xffff)))
                    )
                )
            }
        }
    }
}

/// @notice Calldata packer that also returns the centered norm and range flag for the compact coefficients.
function _packFromCompactCalldataWithNorm(uint256[] calldata c)
    pure
    returns (uint256[] memory A, uint256 norm, uint256 outOfRange)
{
    A = new uint256[](128);
    assembly ("memory-safe") {
        let src := c.offset
        let dst := add(A, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let ci := calldataload(add(src, shl(5, i)))
            // Check all sixteen uint16 lanes at once. Clear each guard bit
            // before adding 2^15-q, so no addition carries between lanes.
            // An original guard bit or a newly set one means coefficient >= q.
            outOfRange :=
                or(
                    outOfRange,
                    and(
                        or(
                            ci,
                            add(
                                and(ci, 0x7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff7fff),
                                0x4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff4fff
                            )
                        ),
                        0x8000800080008000800080008000800080008000800080008000800080008000
                    )
                )
            let base := add(dst, shl(7, i))
            for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                let s := shl(6, k)
                let v := shr(s, ci)

                let c0 := and(v, 0xffff)
                let c1 := and(shr(16, v), 0xffff)
                let c2 := and(shr(32, v), 0xffff)
                let c3 := and(shr(48, v), 0xffff)

                mstore(add(base, shl(5, k)), or(or(c0, shl(64, c1)), or(shl(128, c2), shl(192, c3))))

                if gt(c0, qs1) { c0 := sub(q, c0) }
                if gt(c1, qs1) { c1 := sub(q, c1) }
                if gt(c2, qs1) { c2 := sub(q, c2) }
                if gt(c3, qs1) { c3 := sub(q, c3) }

                norm := add(norm, add(add(mul(c0, c0), mul(c1, c1)), add(mul(c2, c2), mul(c3, c3))))
            }
        }
    }
}

/// @notice 128 packed words -> 512 one-per-word coefficients, fully reduced.
function _unpackTo512(uint256[] memory A) pure returns (uint256[] memory b) {
    b = new uint256[](512);
    assembly ("memory-safe") {
        let src := add(A, 32)
        let dst := add(b, 32)
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let word := mload(add(src, shl(5, w)))
            let o := add(dst, shl(7, w))
            mstore(o, mod(and(word, _LANE), q))
            mstore(add(o, 32), mod(and(shr(64, word), _LANE), q))
            mstore(add(o, 64), mod(and(shr(128, word), _LANE), q))
            mstore(add(o, 96), mod(shr(192, word), q))
        }
    }
}

/// @notice Forward NTT, in place on 128 packed words.
function _nttFwPacked(uint256[] memory A) pure returns (uint256[] memory) {
    bytes memory psirev =
        hex"00012a3a1be70fcb2ae802d216681fdb0dd6225126100e25299304bc0c7b16e41d2c0a4f25c02c4c2dce24622443254916601e12139f16c4230119701c8f0547090f2b6f2c462ceb23800bc613de2ad312ee254623c20e8012c522202bdb270b0c132fb01f212c19246e1ce12416093e2b681f62299e25312f7528c41dfe2d2b04ec112412181986097a014e059406a007dd232802d90ca90b410cd41c1d27d821931bc6292221860d362e9e260d1f7a0e350d8300911a5b255620a51ce718ea24e701e003fe0009265d0153169f0220297810b61b2e1c841fb02201056526242c48215d033b168709ac007608951c360f6d23211164095c1eff00820b151b03096101ba1c142bd60186030521080ec2016212fd24a11642139426500b2b2bec03f91cec06601c25001b2407214e2a61060100f2126a1fd2258b0e78139b2de003ea139313e01f451c9129ba213d2c96267c0e3e17860bab25fb2776186a268b2bd8085f2e6d1ddc0490149d2b4a0cb001ed20011abd094d1f102e4e0562077808760f4b2f901cca2f610c4d2ffe11550e34134a14ab0a902a6f1dd3067f29100d2406990fd9233a24e21ec3087e11141c4f27000fd50a55144b25251ce205cc235225832077246826bf0b3114d40db6065e27b3151f0c722b8024bd2738203126a222b91bba23c12449029f0bc800f31a4a01a4277f06080f9113290dcb01dc003104ef171b05cb263d2a3029d218cb05e8015e28ea150714f927f8237f118d254f1915199a0a5f2440069d00ae02d3284a2154015b0b6d230e2e57074212920bd61013093928ce0b5c00da0d6a22380f7b024017fe267207a227fe24bf28f40f9720802532009c08e916f4281214d50ebc01a217142e3c15351d5b1d80050d012717d31686028c20510fed214f249a01452a852b872c4d17660487217120300d0110ca2f590a8417491c0f2857063a181726061bc12b5105500f74181a14b120122bdf039a01b907a610e20458081e0fce02c523b305271090220f18502cbe099b02ab0e482fc129e31696247d263a23ce292e24131a931eb018e20efa1b781b8824991fb823ca1aa503f22267031313c1125a12ac228c2f4105291330280002a5190f185a22f9052b25332fcd0c66062b2e52263817120f7524ea009727b22fc72f100dcc2c1607a41c702c8c18890d9519d0008e2bb024e50d6e2c321074242c1a2712ae16fe1f8c01f808fe2da42e5c20110e1217b421f10cbf17bd1df11e8e1d4c1a60128d11611ab12f6e213417e6211704a625860f1415451e492be713d7234308792df71f1d1334201614c32b0326d907b51a3b22472bf017252c07028e0ded06a607c31a6814560c7f2fc917f8191b1ada21c6135418080190294114db15460e7e17cd01d4206d013c2e83281020630f2707822ab21ac603cd2b1b";

    assembly ("memory-safe") {
        psirev := add(psirev, 32)
        let base := add(A, 32)

        // ---- layers t = 256, 128, 64, 32, 16, 8, 4  (twds = t/4 whole words)
        let m := 1
        for { let twds := 64 } gt(twds, 0) { twds := shr(1, twds) } {
            let step := shl(5, twds) // twds words, in bytes
            for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                let mi := add(m, i)
                let S := shr(240, mload(add(psirev, shl(1, mi))))
                let p := add(base, shl(1, mul(i, step))) // word i*2*twds
                let pend := add(p, step)
                for {} lt(p, pend) { p := add(p, 32) } {
                    let pt := add(p, step)
                    let U := mload(p)
                    let x := mul(mload(pt), S)
                    let V := sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289))
                    mstore(pt, sub(add(U, _BIG4Q), V))
                    mstore(p, add(U, V))
                }
            }
            m := shl(1, m)
        }

        // Fuse the two in-word stages: one load, one store, one loop.
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let p := add(base, shl(5, w))
            let W := mload(p)
            {
                let mi := add(128, w)
                let S := shr(240, mload(add(psirev, shl(1, mi))))
                let U := and(W, _L01)
                let x := mul(and(shr(128, W), _L01), S)
                let V := sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289))
                W := or(and(add(U, V), _L01), shl(128, and(sub(add(U, _BIG4Q), V), _L01)))
            }
            {
                let twiddles := shr(224, mload(add(psirev, add(512, shl(2, w)))))
                let Sa := shr(16, twiddles)
                let Sb := and(twiddles, 0xffff)
                let Ua := and(W, _L0)
                let xa := mul(and(shr(64, W), _L0), Sa)
                let Va := mod(xa, 12289)
                let Ub := and(shr(128, W), _L0)
                let xb := mul(shr(192, W), Sb)
                let Vb := mod(xb, 12289)
                mstore(
                    p,
                    or(
                        or(and(add(Ua, Va), _LANE), shl(64, and(sub(add(Ua, _BIG4Q), Va), _LANE))),
                        or(shl(128, and(add(Ub, Vb), _LANE)), shl(192, and(sub(add(Ub, _BIG4Q), Vb), _LANE)))
                    )
                )
            }
        }
    }
    return A;
}

/// @notice Lane-wise product of two packed polynomials, fully Barrett-reduced.
/// @dev SWAR cannot multiply two packed vectors (lanes cross-contaminate), so
///      each of the four lanes is extracted and multiplied on its own. The win
///      over _ZKNOX_VECMULMOD is not the arithmetic, it is never materialising
///      the 512-word expanded form.
function _vecMulPacked(uint256[] memory A, uint256[] memory B) pure returns (uint256[] memory C) {
    C = new uint256[](128);
    assembly ("memory-safe") {
        let pa := add(A, 32)
        let pb := add(B, 32)
        let pcw := add(C, 32)
        let endp := add(pcw, 4096) // 128 words
        for {} lt(pcw, endp) {} {
            let x := mload(pa)
            let y := mload(pb)
            mstore(
                pcw,
                or(
                    or(
                        mulmod(and(x, _LANE), and(y, _LANE), 12289),
                        shl(64, mulmod(and(shr(64, x), _LANE), and(shr(64, y), _LANE), 12289))
                    ),
                    or(
                        shl(128, mulmod(and(shr(128, x), _LANE), and(shr(128, y), _LANE), 12289)),
                        shl(192, mulmod(shr(192, x), shr(192, y), 12289))
                    )
                )
            )
            pa := add(pa, 32)
            pb := add(pb, 32)
            pcw := add(pcw, 32)
        }
    }
}

/// @notice Multiply in place by a compact calldata key, avoiding two 128-word
/// allocations and a separate unpacking pass. Key lanes retain their existing
/// uint16 interpretation; MULMOD also handles noncanonical key residues.
function _vecMulCompactCalldataInPlace(uint256[] memory A, uint256[] calldata key) pure returns (uint256[] memory) {
    assembly ("memory-safe") {
        let dst := add(A, 32)
        let end := add(dst, 4096)
        let src := key.offset
        for {} lt(dst, end) { src := add(src, 32) } {
            let keyWord := calldataload(src)
            for { let shift := 0 } lt(shift, 256) { shift := add(shift, 64) } {
                let x := mload(dst)
                let y := shr(shift, keyWord)
                mstore(
                    dst,
                    or(
                        or(
                            mulmod(and(x, _LANE), and(y, 0xffff), q),
                            shl(64, mulmod(and(shr(64, x), _LANE), and(shr(16, y), 0xffff), q))
                        ),
                        or(
                            shl(128, mulmod(and(shr(128, x), _LANE), and(shr(32, y), 0xffff), q)),
                            shl(192, mulmod(shr(192, x), and(shr(48, y), 0xffff), q))
                        )
                    )
                )
                dst := add(dst, 32)
            }
        }
    }
    return A;
}

/// @notice Inverse NTT (Gentleman-Sande), in place on 128 packed words.
/// @dev Sums are left unreduced. Before stage k (1-based), each lane is
///      < 2^(k-1)*q (the first two stages also use a conservative 4q bias).
///      Word-aligned subtraction uses the matching doubling bias, so lanes
///      never borrow. At the end lanes are < 512q. Both the largest twiddle
///      product and the final scaling product are < 512q^2 < 2^37;
///      multiplying by floor(2^40/q) stays below 2^64. Thus packed Barrett
///      reduction remains lane-independent and yields a residue < 2q.
function _nttInvPacked(uint256[] memory A) pure returns (uint256[] memory) {
    bytes memory psirev =
        hex"000105c72036141a102619992d2f0519191d23862b45066e21dc09f10db0222b2aba137216910d00193d1c6211ef19a10ab80bbe0b9f023303b50a4125b212d502d61203073d008c0ad00663109f049926c30beb13200b9303e810e0005123ee08f604260de11d3c21810c3f0abb1d13052e1c23243b0c81031603bb049226f214fe24ec2f7f110226a51e9d0ce0209413cb276c2f8b2655197a2cc60ea403b909dd2a9c0e001051137d14d31f4b06892de119622eae09a42ff82c032e210b1a1717131a0f5c0aab15a62f70227e21cc108709f4016322cb0e7b06df143b0e6e082913e4232d24c023582d280cd9282429612a6d2eb32687167b1de91edd2b152e2522361cd8207029f908822e5d15b72f0e24392d620bb80c4014470d48095f0fd008c90b440481238f1ae2084e29a3224b1b2d24d009420b990f8a0a7e0caf2a35131f0adc1bb625ac202c090113b21eed2783113e0b1f0cc72028296822dd06f12982122e059225711b561cb721cd1eac000323b400a01337007120b6278b28892a9f01b310f126b4154410002e14235104b71b642b711225019427a2042909761797088b0a062456187b21c30985036b0ec40647137010bc1c211c6e2c1702211c6621890a76102f1d972f0f2a0005a00eb30bfa2fe613dc29a113152c08041524d609b11c6d19bf0b601d042e9f213f0ef92cfc2e7b042b13ed2e4726a004e62c34153b054f287f20da0f9e07f1017e2ec50f942e2d183421831abb1b2606c02e7117f91cad0e3b152716e61809003823821bab1599283e295b22142d7303fa18dc04110dba15c6284c092804fe1b3e0feb1ccd10e4020a27880cbe1c2a041a11b81abc20ed0a7b2b5b0eea181b0ecd009315501ea01d7415a112b511731210184423420e10184d21ef0ff001a5025d27032e09107519031d5315da0bd51f8d03cf22930b1c04512f731631226c177803751391285d03eb223500f1003a084f2f6a0b17208c18ef09c901af29d6239b00340ace2ad60d0817a716f22d5c08011cd12ad800c00d751d551da71c402cee0d9a2c0f155c0c3710490b68147914892107171f1151156e0bee06d30c3309c70b84196b061e004021b92d562666034317b10df21f712ada0c4e2d3c203327e32ba91f1f285b2e482c6704220fef1b5017e7208d2ab104b0144009fb17ea29c707aa13f218b8257d00a81f3723000fd10e902b7a189b03b4047a057c2ebc0b670eb220140fb02d75197b182e2eda2af4128112a61acc01c518ed2e5f21451b2c07ef190d27182f650acf0f81206a070d0b420803285f098f18032dc120860dc922972f2724a5073326c81fee242b1d6f28bf01aa0cf324942ea60ead07b72d2e2f5329640bc125a2166716ec0ab21e740c8208091b081afa07172ea32a191736062f05d109c42a3618e62b122fd0";

    assembly ("memory-safe") {
        psirev := add(psirev, 32)
        let base := add(A, 32)

        // Fuse the two in-word inverse stages.
        for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
            let p := add(base, shl(5, w))
            let W := mload(p)
            {
                let l0 := and(W, _LANE)
                let l1 := and(shr(64, W), _LANE)
                let l2 := and(shr(128, W), _LANE)
                let l3 := shr(192, W)

                let twiddles := shr(224, mload(add(psirev, add(512, shl(2, w)))))
                let Sa := shr(16, twiddles)
                let Sb := and(twiddles, 0xffff)

                let s0 := add(l0, l1)
                let d0 := mul(sub(add(l0, 49156), l1), Sa)
                d0 := mod(d0, 12289)
                let s1 := add(l2, l3)
                let d1 := mul(sub(add(l2, 49156), l3), Sb)
                d1 := mod(d1, 12289)

                W :=
                    or(or(and(s0, _LANE), shl(64, and(d0, _LANE))), or(shl(128, and(s1, _LANE)), shl(192, and(d1, _LANE))))
            }
            {
                let mi := add(128, w)
                let S := shr(240, mload(add(psirev, shl(1, mi))))
                let U := and(W, _L01)
                let V := and(shr(128, W), _L01)
                let s := add(U, V)
                let d := mul(and(sub(add(U, _BIG4Q), V), _L01), S)
                d := sub(d, mul(and(shr(40, mul(d, 89471204)), _MASK24L), 12289))
                mstore(p, or(and(s, _L01), shl(128, and(d, _L01))))
            }
        }

        // ---- t = 4 .. 256, word aligned
        let m := 128
        for { let twds := 1 } gt(m, 1) { twds := shl(1, twds) } {
            let h := shr(1, m)
            let step := shl(5, twds)
            let stride := shl(1, step)
            let g := base
            for { let i := 0 } lt(i, h) { i := add(i, 1) } {
                let hi := add(h, i)
                let S := shr(240, mload(add(psirev, shl(1, hi))))
                let p := g
                let pend := add(p, step)
                for {} lt(p, pend) { p := add(p, 32) } {
                    let pt := add(p, step)
                    let U := mload(p)
                    let V := mload(pt)
                    let s := add(U, V)
                    let d := mul(sub(add(U, mul(twds, _BIG4Q)), V), S)
                    d := sub(d, mul(and(shr(40, mul(d, 89471204)), _MASK24L), 12289))
                    mstore(p, s)
                    mstore(pt, d)
                }
                g := add(g, stride)
            }
            m := shr(1, m)
        }

        // ---- final scaling by n^-1 mod q
        let p := base
        let pend := add(base, 4096)
        for {} lt(p, pend) { p := add(p, 32) } {
            let x := mul(mload(p), nm1modq)
            mstore(p, sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289)))
        }
    }
    return A;
}

/// @notice 128 packed words -> 32 compact words (16 x 16-bit), fully reduced.
function _compactFromPacked(uint256[] memory A) pure returns (uint256[] memory c) {
    c = new uint256[](32);
    assembly ("memory-safe") {
        let src := add(A, 32)
        let dst := add(c, 32)
        for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
            let acc := 0
            let base := add(src, shl(7, i))
            for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                let word := mload(add(base, shl(5, k)))
                let v :=
                    or(
                        or(mod(and(word, _LANE), q), shl(16, mod(and(shr(64, word), _LANE), q))),
                        or(shl(32, mod(and(shr(128, word), _LANE), q)), shl(48, mod(shr(192, word), q)))
                    )
                acc := or(acc, shl(shl(6, k), v))
            }
            mstore(add(dst, shl(5, i)), acc)
        }
    }
}
