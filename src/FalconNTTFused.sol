// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./FalconNTT.sol";

/// @notice Compute inverseNTT(NTT(A) * key) in place.
/// @dev A contains 512 canonical residues in four 64-bit lanes per word.
/// The middle kernel combines both in-word forward stages, the calldata key
/// multiplication, and both in-word inverse stages without spilling their
/// intermediate polynomials to memory. High stages retain the original lane
/// bounds; the middle kernel leaves each lane below 4q for the inverse tail.
function falconProductFused(uint256[] memory A, uint256[] calldata key) pure returns (uint256[] memory) {
    // Big-endian uint16 table: forward[0:128], inverse[0:128], followed by
    // (forward, inverse) pairs for stages 2, 1a, 1b of each four-lane word.
    bytes memory twiddles =
        hex"00012a3a1be70fcb2ae802d216681fdb0dd6225126100e25299304bc0c7b16e41d2c0a4f25c02c4c2dce24622443254916601e12139f16c4230119701c8f0547090f2b6f2c462ceb23800bc613de2ad312ee254623c20e8012c522202bdb270b0c132fb01f212c19246e1ce12416093e2b681f62299e25312f7528c41dfe2d2b04ec112412181986097a014e059406a007dd232802d90ca90b410cd41c1d27d821931bc6292221860d362e9e260d1f7a0e350d8300911a5b255620a51ce718ea24e701e003fe0009265d0153169f0220297810b61b2e1c841fb02201056526242c48215d033b168709ac007608951c360f6d23211164095c1eff00820b151b03000105c72036141a102619992d2f0519191d23862b45066e21dc09f10db0222b2aba137216910d00193d1c6211ef19a10ab80bbe0b9f023303b50a4125b212d502d61203073d008c0ad00663109f049926c30beb13200b9303e810e0005123ee08f604260de11d3c21810c3f0abb1d13052e1c23243b0c81031603bb049226f214fe24ec2f7f110226a51e9d0ce0209413cb276c2f8b2655197a2cc60ea403b909dd2a9c0e001051137d14d31f4b06892de119622eae09a42ff82c032e210b1a1717131a0f5c0aab15a62f70227e21cc108709f4016322cb0e7b06df143b0e6e082913e4232d24c023582d280cd9282429612a6d2eb32687167b1de91edd2b1509612e25003104e604ef2c3401ba2236171b153b05cb054f1c141cd8263d287f2a3020da2bd6207029d20f9e18cb07f1018629f905e8017e015e2ec50305088228ea0f9415072e2d21082e5d14f9183427f821830ec215b7237f1abb118d1b2601622f0e254f06c019152e7112fd2439199a17f90a5f1cad24a12d6224400e3b069d152716420bb800ae16e602d3180913940c40284a00382154238226501447015b1bab0b6d15990b2b0d48230e283e2e57295b2bec095f0742221412922d7303f90fd00bd603fa101318dc1cec08c90939041128ce0dba06600b440b5c15c600da284c1c2504810d6a0928223804fe001b238f0f7b1b3e02400feb24071ae217fe1ccd267210e4214e084e07a2020a27fe27882a6129a324bf0cbe28f41c2a0601224b0f97041a208011b800f21b2d25321abc009c20ed126a24d008e90a7b16f42b5b1fd2094228120eea14d5181b258b0b990ebc0ecd01a200930e780f8a171415502e3c1ea0139b0a7e15351d741d5b15a12de00caf1d8012b5050d117303ea2a350127121017d318441393131f16862342028c0e1013e00adc2051184d0fed21ef1f451bb6214f0ff0249a01a51c9125ac0145025d2a85270329ba202c2b872e092c4d1075213d09011766190304871d532c9613b2217115da20300bd5267c1eed0d011f8d10ca03cf0e3e27832f5922930a840b1c1786113e174904511c0f2f730bab0b1f28571631063a226c25fb0cc71817177826060375277620281bc113912b51285d186a2968055003eb0f742235268b22dd181a00f114b1003a2bd806f12012084f2bdf2f6a085f2982039a0b1701b9208c2e6d122e07a618ef10e209c91ddc0592045801af081e29d6049025710fce239b02c50034149d1b5623b30ace05272ad62b4a1cb710900d08220f17a70cb021cd185016f22cbe2d5c01ed1eac099b080102ab1cd1200100030e482ad82fc100c01abd23b429e30d7516961d55094d00a0247d1da7263a1c401f10133723ce2cee292e0d9a2e4e007124132c0f1a93155c056220b61eb00c3718e210490778278b0efa0b681b781479087628891b881489249921070f4b2a9f1fb8171f23ca11512f9001b31aa5156e03f20bee1cca10f1226706d303130c332f6126b413c109c7125a0b840c4d154412ac196b228c061e2ffe10002f410040052921b911552e1413302d56280026660e34235102a50343190f17b1134a04b7185a0df222f91f7114ab1b64052b2ada25330c4e0a902b712fcd2d3c0c6620332a6f1225062b27e32e522ba91dd3019426381f1f1712285b067f27a20f752e4824ea2c67291004290097042227b20fef0d2409762fc71b502f1017e7069917970dcc208d2c162ab10fd9088b07a404b01c701440233a0a062c8c09fb188917ea24e224560d9529c719d007aa1ec3187b008e13f22bb018b8087e21c324e5257d0d6e00a8111409852c321f37107423001c4f036b242c0fd11a270e9027000ec412ae2b7a16fe189b0fd506471f8c03b401f8047a0a55137008fe057c2da42ebc144b10bc2e5c0b6720110eb225251c210e12201417b40fb01ce21c6e21f12d750cbf197b05cc2c1717bd182e1df12eda235202211e8e2af41d4c128125831c661a6012a6128d1acc20772189116101c51ab118ed24680a762f6e2e5f2134214526bf102f17e61b2c211707ef0b311d9704a6190d2586271814d42f0f0f142f6515450acf0db62a001e490f812be7206a065e05a013d7070d23430b4227b30eb3087908032df7285f151f0bfa1f1d098f133418030c722fe620162dc114c320862b8013dc2b030dc926d9229724bd29a107b52f271a3b24a527381315224707332bf026c820312c0817251fee2c07242b26a20415028e1d6f0ded28bf22b924d606a601aa07c30cf31bba09b11a68249414562ea623c11c6d0c7f0ead2fc907b7244919bf17f82d2e191b2f53029f0b601ada296421c60bc10bc81d04135425a21808166700f32e9f019016ec29410ab21a4a213f14db1e7415460c8201a40ef90e7e080917cd1b08277f2cfc01d41afa206d071706082e7b013c2ea32e832a190f91042b281017362063062f132913ed0f2705d1078209c40dcb2e472ab22a361ac618e601dc26a003cd2b122b1b2fd0";
    assembly ("memory-safe") {
        function reduce4(x) -> r {
            r := sub(x, mul(and(shr(40, mul(x, 89471204)), _MASK24L), 12289))
        }
        // tw encodes forward then inverse twiddle; h has two uint16 key lanes.
        function pair(u, v, tw, h) -> r {
            let x := mod(mul(v, shr(16, tw)), 12289)
            let a := mulmod(add(u, x), and(h, 0xffff), 12289)
            let b := mulmod(sub(add(u, 49156), x), shr(16, h), 12289)
            let d := mulmod(sub(add(a, 12289), b), and(tw, 0xffff), 12289)
            r := or(add(a, b), shl(64, d))
        }
        let base := add(A, 32)
        let table := add(twiddles, 32)
        {
            // Forward word-aligned stages, t = 256 through 4.
            let m := 1
            for { let twds := 64 } gt(twds, 0) { twds := shr(1, twds) } {
                let step := shl(5, twds)
                for { let i := 0 } lt(i, m) { i := add(i, 1) } {
                    let s := shr(240, mload(add(table, shl(1, add(m, i)))))
                    let p := add(base, shl(1, mul(i, step)))
                    let end := add(p, step)
                    for {} lt(p, end) { p := add(p, 32) } {
                        let pt := add(p, step)
                        let u := mload(p)
                        let v := reduce4(mul(mload(pt), s))
                        mstore(pt, sub(add(u, _BIG4Q), v))
                        mstore(p, add(u, v))
                    }
                }
                m := shl(1, m)
            }
        }
        {
            let middle := add(table, 512)
            for { let w := 0 } lt(w, 128) { w := add(w, 1) } {
                let p := add(base, shl(5, w))
                let tw := mload(add(middle, mul(w, 12)))
                let word := mload(p)
                // Forward t=2 butterfly, two parallel lanes.
                {
                    let u := and(word, _L01)
                    let v := reduce4(mul(shr(128, word), shr(240, tw)))
                    word := or(and(add(u, v), _L01), shl(128, sub(add(u, _BIG4Q), v)))
                }
                // Each eight-byte slice holds four compact key coefficients.
                let h := shr(192, calldataload(add(key.offset, xor(shl(3, w), 24))))
                let a :=
                    pair(and(word, _LANE), and(shr(64, word), _LANE), and(shr(192, tw), 0xffffffff), and(h, 0xffffffff))
                let b := pair(and(shr(128, word), _LANE), shr(192, word), and(shr(160, tw), 0xffffffff), shr(32, h))
                // Inverse t=2 butterfly; a,b have lanes below 2q.
                let d := reduce4(mul(and(sub(add(a, _BIG4Q), b), _L01), and(shr(224, tw), 0xffff)))
                mstore(p, or(add(a, b), shl(128, d)))
            }
        }
        {
            let inverse := add(table, 256)
            let m := 128
            for { let twds := 1 } gt(m, 2) { twds := shl(1, twds) } {
                let h := shr(1, m)
                let step := shl(5, twds)
                let stride := shl(1, step)
                let g := base
                for { let i := 0 } lt(i, h) { i := add(i, 1) } {
                    let s := shr(240, mload(add(inverse, shl(1, add(h, i)))))
                    let p := g
                    let end := add(p, step)
                    for {} lt(p, end) { p := add(p, 32) } {
                        let pt := add(p, step)
                        let u := mload(p)
                        let v := mload(pt)
                        let d := reduce4(mul(sub(add(u, mul(twds, _BIG4Q)), v), s))
                        mstore(p, add(u, v))
                        mstore(pt, d)
                    }
                    g := add(g, stride)
                }
                m := shr(1, m)
            }
        }
        // Fuse the last inverse stage with n^-1 scaling. Both branches
        // need just one packed Barrett reduction, and no scaling pass remains.
        // 1371 = inverseRoot[1] * 512^-1 mod q.
        for { let p := base } lt(p, add(base, 2048)) { p := add(p, 32) } {
            let pt := add(p, 2048)
            let u := mload(p)
            let v := mload(pt)
            mstore(p, reduce4(mul(add(u, v), 12265)))
            mstore(pt, reduce4(mul(sub(add(u, mul(64, _BIG4Q)), v), 1371)))
        }
    }
    return A;
}
