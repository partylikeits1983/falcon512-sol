// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./FalconNTT.sol";

uint256 constant _M16L32 = 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;
uint256 constant _ONES32 = 0x0000000100000001000000010000000100000001000000010000000100000001;
uint256 constant _GUARD4Q32 = 0x7fff3ffc7fff3ffc7fff3ffc7fff3ffc7fff3ffc7fff3ffc7fff3ffc7fff3ffc;
uint256 constant _Q2L32 = 0x0000600200006002000060020000600200006002000060020000600200006002;
uint256 constant _Q4L32 = 0x0000c0040000c0040000c0040000c0040000c0040000c0040000c0040000c004;
uint256 constant _PAIR64 = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
uint256 constant _M16L64 = 0x000000000000ffff000000000000ffff000000000000ffff000000000000ffff;

uint256 constant _Q3L32 = 0x0000900300009003000090030000900300009003000090030000900300009003;
uint256 constant _M8L32 = 0x000000ff000000ff000000ff000000ff000000ff000000ff000000ff000000ff;

/// @notice Compatibility entry for canonical four-lane packed inputs.
function falconProductMontgomery8(uint256[] memory A, uint256[] calldata key) pure returns (uint256[] memory) {
    assembly ("memory-safe") {
        function compress4(x) -> r {
            x := and(or(x, shr(32, x)), _PAIR64)
            r := and(or(x, shr(64, x)), _L01)
        }
        let base := add(A, 32)
        // Contract forward in place; unread source words are always ahead.
        for { let w := 0 } lt(w, 64) { w := add(w, 1) } {
            let src := add(base, shl(6, w))
            mstore(add(base, shl(5, w)), or(compress4(mload(src)), shl(128, compress4(mload(add(src, 32))))))
        }
    }
    return expandProduct8(falconProductMontgomery8Native(A, key));
}

/// @notice Validate, center, and pack compact signature coefficients as eight lanes.
/// @dev Eight coefficients per word: only 64 words are allocated.
/// The norm is meaningful only when outOfRange == 0.
function packSignature8(uint256[] calldata signature)
    pure
    returns (uint256[] memory A, uint256 norm, uint256 outOfRange)
{
    A = new uint256[](64);
    assembly ("memory-safe") {
        function pack8(v) -> r {
            // Spread eight uint16 coefficients into eight uint32 lanes.
            v := and(or(v, shl(64, v)), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)
            v := and(or(v, shl(32, v)), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
            r := and(or(v, shl(16, v)), _M16L32)
        }
        function norm8(v) -> r {
            // Guard bit 15 marks v >= 6145 independently in each lane.
            let signs :=
                and(shr(15, add(v, 0x000067ff000067ff000067ff000067ff000067ff000067ff000067ff000067ff)), _ONES32)
            let a := and(add(xor(v, mul(signs, 65535)), mul(signs, 12290)), _M16L32)
            // For negative coefficients: (~v & 65535) + q + 1, modulo
            // 65536, equals q-v. No intermediate reaches the next lane.
            let rev := or(shl(128, a), shr(128, a))
            let mask := and(rev, _PAIR64)
            rev := or(shl(64, mask), shr(64, xor(rev, mask)))
            mask := and(rev, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)
            rev := or(shl(32, mask), shr(32, xor(rev, mask)))
            // The degree-seven coefficient of a * reverse(a) is the sum
            // of eight squares. Every product coefficient is <=8*6144^2
            // <2^32, so lower coefficients cannot carry into this lane.
            r := shr(224, mul(a, rev))
        }
        let base := add(A, 32)
        for { let w := 0 } lt(w, 64) { w := add(w, 1) } {
            let v := shr(128, calldataload(add(signature.offset, xor(shl(4, w), 16))))
            outOfRange := or(
                outOfRange,
                and(
                    or(v, add(and(v, 0x7fff7fff7fff7fff7fff7fff7fff7fff), 0x4fff4fff4fff4fff4fff4fff4fff4fff)),
                    0x80008000800080008000800080008000
                )
            )
            let packed := pack8(v)
            mstore(add(base, shl(5, w)), packed)
            norm := add(norm, norm8(packed))
        }
    }
}

/// @notice Eight parallel 32-bit lanes, with Montgomery twiddles and fused low stages.
/// @dev Input/output are 64 eight-lane words. Each input lane must be <q.
/// Forward stage bounds are 3q,5q,7q,10q,13q,17q;
/// a single Barrett step before the middle kernel reduces to <2q. Inverse
/// high-stage lanes are normalized below 4q.
/// REDC uses R=2^16 and -q^-1=12287 mod R. Masking before the correction multiply
/// prevents adjacent 32-bit lanes from carrying into one another.
function falconProductMontgomery8Native(uint256[] memory A, uint256[] calldata key) pure returns (uint256[] memory) {
    bytes memory twiddles =
        hex"0ffb1ed02b342bc81b3010f61883261f063718ff25051492024a16c11d7225ee046e190706af03c51bbb1dfa0e9f192a28ae1fa4075d06980554285927b423dc2fb2186003e5007512af1137060d1ba00b0d193a114f22ad1be80a0416200fca2f9d01b029ff04d51dba05fe0f8f1eb7088518a4221019aa12eb069a000e0f200ffb1131043904cd09e2177e1f0b14d10a13128f19402db71b6f0afc170229ca0c25084d07a82aad296928a4105d075316d72162120714462c3c295216fa2b9320e12ff329671d1616570df1175d277c114a20722a0312472b2c06022e510064203719e125fd14190d541eb216c724f4146129f41eca1d522f8c2c1c17a1004f15c1000d0dfc19eb003104e604ef2c3406cb198f171b153b05cb054f24981b1a2a44062e263d287f2a3020da263b130429d20f9e18cb07f12f8322b627e1002a05e8017e015e2ec50fe602a128ea0f9415072e2d07e3154d2fda08c014f9183427f82183214d1c33237f1abb118d1b261d7711ea28a10510254f06c019152e710abd2ed5199a17f90a5f1cad090b2cbf1caa1dfb24400e3b069d1527294e218200ae16e602d3180912410b5717982ead284a00382154238203af03dd015b1bab0b6d15991cac12442472292d230e283e2e57295b05c51e070742221412922d73061126731ad11bad0bd603fa101318dc25c421270939041128ce0dba04841dc50e0103ec0b5c15c600da284c19e927fc0d6a0928223804fe20d122762f71125f0f7b1b3e02400feb0fdf00a317fe1ccd267210e42c7d23950e6423b707a2020a27fe27881e0011f524bf0cbe28f41c2a03fc08231ffc191f0f97041a208011b81af62f1425321abc009c20ed0b97213b0dcd0baf08e90a7b16f42b5b264f2ea228120eea14d5181b2a1421ed17ca12270ebc0ecd01a2009302d70d22171415502e3c1ea01b850c262773080c15351d741d5b15a11b5b2c5d1d8012b5050d11730cf41b671b212eeb0127121017d31844079d1a0816862342028c0e102be40cc5260316172051184d0fed21ef293f1c39214f0ff0249a01a514a5055717a9171a0145025d2a852703017a246f2b872e092c4d10752d3a18fd1ebf0ffc1766190304871d53223b16f8217115da20300bd5298d281322c51b140d011f8d10ca03cf240d0d4a2f5922930a840b1c276620f3228e140d174904511c0f2f7311c724b228571631063a226c2515291f25752bdd18171778260603752d9014841bc113912b51285d18242d271dce2330055003eb0f74223522750614181a00f114b1003a243d2b5616301afc2012084f2bdf2f6a135c12a5039a0b1701b9208c17f208a3186b0f0d07a618ef10e209c920c4224c045801af081e29d60cfb071027ac28550fce239b02c5003422131e3923b30ace05272ad603731c97092506de10900d08220f17a70c571bbf185016f22cbe2d5c28e5003005bb2c6f099b080102ab1cd115542ff10e482ad82fc100c001e9254b2169219a29e30d7516961d551e670cab247d1da7263a1c4005de0a000a59198823ce2cee292e0d9a09101da624132c0f1a93155c0b2304cc234c218f1eb00c3718e21049182c2d200efa0b681b7814792b3524de02e117d51b881489249921070e720cb51fb8171f23ca115126012a23125b26f11aa5156e03f20bee167925a8226706d303130c330ab62e182356119a13c109c7125a0b840e670e9812ac196b228c061e2fd1071c00101aad2f410040052921b903922a4613302d5628002666136a2c8e144223aa02a50343190f17b1292326dc185a0df222f91f7128f1230611c80dee052b2ada25330c4e07ac08552fcd2d3c0c662033275e180f0db50f3d062b27e32e522ba920f4179626381f1f1712285b04ab0bc41d5c1ca50f752e4824ea2c67150519d10097042227b20fef02da17dd29ed0d8c2fc71b502f1017e70cd112330dcc208d2c162ab106e20aec1b7d027107a404b01c70144004240a8c2c8c09fb188917ea0f0e089b0b4f1e3a0d9529c719d007aa1bf40d73008e13f22bb018b807ee067422b70bf424e5257d0d6e00a814ed0d3c2c321f3710742300170402c719090dc6242c0fd11a270e902005114212ae2b7a16fe189b2aaa1b5c0b922e871f8c03b401f8047a18e7185808fe057c2da42ebc233c041d13c806c22e5c0b6720110eb219ea09fe0e12201417b40fb0149a230d15f9286421f12d750cbf197b011614e017bd182e1df12eda23db147c03a414a61e8e2af41d4c128127f5088e1a6012a6128d1acc0e1405ed22df2d2a116101c51ab118ed1dda18372f6e2e5f213421450ec6246a015f09b217e61b2c211707ef2452223404a6190d2586271827de2c0500ed150b0f142f6515450acf16e210051e490f812be7206a0c6c03841e0c120113d7070d23430b420c4a219d087908032df7285f0d8b0f302f5e20221f1d098f133418031da2009020162dc114c32086123c2b7d080516182b030dc926d922972c15220007b52f271a3b24a5098e29f00eda0a3d224707332bf026c81454153017251fee2c07242b1dbd135511fa2a3c028e1d6f0ded28bf06d40b8f06a601aa07c30cf324aa1dc02c242c521a68249414562ea6015418690c7f0ead2fc907b7034226f60e7f06b317f82d2e191b2f53120613571ada296421c60bc11e17128a012c2544135425a2180816672af10760019016ec29410ab21ab4281e13ce0eb414db1e7415460c82274100270e7e080917cd1b080d4b007e2d60201b01d41afa206d07172fd70820013c2ea32e832a1914e70b691cfd09c6281017362063062f29d305bd0f2705d1078209c42ff41a40167229362ab22a361ac618e61616220503cd2b122b1b2fd0";
    assembly ("memory-safe") {
        function mont(x) -> r {
            let m := and(mul(and(x, _M16L32), 12287), _M16L32)
            r := and(shr(16, add(x, mul(m, 12289))), _M16L32)
        }
        function bound4q(x) -> r {
            r := sub(x, mul(and(shr(31, add(x, _GUARD4Q32)), _ONES32), 49156))
        }
        function pair(u, v, tw, h) -> r {
            let x := mod(mul(v, shr(16, tw)), 12289)
            let a := mulmod(add(u, x), and(h, 0xffff), 12289)
            let b := mulmod(sub(add(u, 49156), x), shr(16, h), 12289)
            let d := mulmod(sub(add(a, 12289), b), and(tw, 0xffff), 12289)
            r := or(add(a, b), shl(32, d))
        }
        function middle4(word, tw, h) -> r {
            let u := and(word, _LANE)
            let v := mont(mul(shr(64, word), shr(240, tw)))
            // Incoming lanes are <6q here; mont(v*S) is <3q.
            let a := add(u, v)
            let b := and(sub(add(u, _Q4L32), v), _LANE)
            let c := pair(and(a, 0xffffffff), shr(32, a), and(shr(192, tw), 0xffffffff), and(h, 0xffffffff))
            let d := pair(and(b, 0xffffffff), shr(32, b), and(shr(160, tw), 0xffffffff), shr(32, h))
            let difference := mont(mul(and(sub(add(c, _Q2L32), d), _LANE), and(shr(224, tw), 0xffff)))
            r := or(add(c, d), shl(64, difference))
        }
        mstore(A, 64)
        let base := add(A, 32)
        let table := add(twiddles, 32)
        // BEGIN GENERATED FORWARD
        {
            {
                let p := base
                let s := shr(240, mload(add(table, 2)))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 128)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 160)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 192)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 224)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 256)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 288)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 320)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 352)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 384)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 416)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 448)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 480)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 512)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 544)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 576)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 608)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 640)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 672)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 704)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 736)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 768)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 800)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 832)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 864)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 896)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 928)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 960)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 992)
                    let pt := add(pa, 1024)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
            }

            for { let w := 0 } lt(w, 2) { w := add(w, 1) } {
                let p := add(base, mul(1024, w))
                let s := shr(240, mload(add(add(table, 4), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 128)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 160)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 192)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 224)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 256)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 288)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 320)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 352)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 384)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 416)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 448)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 480)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
            }

            for { let w := 0 } lt(w, 4) { w := add(w, 1) } {
                let p := add(base, mul(512, w))
                let s := shr(240, mload(add(add(table, 8), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 128)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 160)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 192)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
                {
                    let pa := add(p, 224)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q2L32), v))
                }
            }

            for { let w := 0 } lt(w, 8) { w := add(w, 1) } {
                let p := add(base, mul(256, w))
                let s := shr(240, mload(add(add(table, 16), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q3L32), v))
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q3L32), v))
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q3L32), v))
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q3L32), v))
                }
            }

            for { let w := 0 } lt(w, 16) { w := add(w, 1) } {
                let p := add(base, mul(128, w))
                let s := shr(240, mload(add(add(table, 32), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 64)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q3L32), v))
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 64)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q3L32), v))
                }
            }

            for { let w := 0 } lt(w, 32) { w := add(w, 1) } {
                let p := add(base, mul(64, w))
                let s := shr(240, mload(add(add(table, 64), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 32)
                    let u := mload(pa)

                    let v := mont(mul(mload(pt), s))
                    mstore(pa, add(u, v))
                    mstore(pt, sub(add(u, _Q4L32), v))
                }
            }
        }
        // END GENERATED FORWARD
        {
            let middle := add(table, 256)
            for { let w := 0 } lt(w, 64) { w := add(w, 1) } {
                let p := add(base, shl(5, w))
                let tw := mload(add(middle, mul(w, 28)))
                let word := mload(p)
                // After six forward stages lanes are <17q. A single packed
                // Barrett step with floor(2^18/q)=21 leaves lanes below 2q.
                word := sub(word, mul(and(shr(18, mul(word, 21)), _M8L32), 12289))
                let u := and(word, _L01)
                let v := mont(mul(shr(128, word), shr(240, tw)))
                // Forward t=4, then both fused four-lane kernels.
                let h := shr(128, calldataload(add(key.offset, xor(shl(4, w), 16))))
                let a := middle4(and(add(u, v), _L01), shl(32, tw), and(h, _LANE))
                let b := middle4(and(sub(add(u, _Q2L32), v), _L01), shl(128, tw), shr(64, h))
                let d := mont(mul(and(sub(add(a, _Q4L32), b), _L01), and(shr(224, tw), 0xffff)))
                mstore(p, or(bound4q(add(a, b)), shl(128, d)))
            }
        }
        // BEGIN GENERATED INVERSE
        {
            let inverse := add(table, 128)

            for { let w := 0 } lt(w, 32) { w := add(w, 1) } {
                let p := add(base, mul(64, w))
                let s := shr(240, mload(add(add(inverse, 64), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 32)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
            }

            for { let w := 0 } lt(w, 16) { w := add(w, 1) } {
                let p := add(base, mul(128, w))
                let s := shr(240, mload(add(add(inverse, 32), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 64)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 64)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
            }

            for { let w := 0 } lt(w, 8) { w := add(w, 1) } {
                let p := add(base, mul(256, w))
                let s := shr(240, mload(add(add(inverse, 16), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 128)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
            }

            for { let w := 0 } lt(w, 4) { w := add(w, 1) } {
                let p := add(base, mul(512, w))
                let s := shr(240, mload(add(add(inverse, 8), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 128)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 160)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 192)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 224)
                    let pt := add(pa, 256)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
            }

            for { let w := 0 } lt(w, 2) { w := add(w, 1) } {
                let p := add(base, mul(1024, w))
                let s := shr(240, mload(add(add(inverse, 4), shl(1, w))))
                {
                    let pa := add(p, 0)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 32)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 64)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 96)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 128)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 160)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 192)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 224)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 256)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 288)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 320)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 352)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 384)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 416)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 448)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
                {
                    let pa := add(p, 480)
                    let pt := add(pa, 512)
                    let u := mload(pa)

                    let v := mload(pt)
                    let d := mont(mul(sub(add(u, _Q4L32), v), s))
                    mstore(pa, bound4q(add(u, v)))
                    mstore(pt, d)
                }
            }
        }
        // END GENERATED INVERSE
        // 128 = R/512; 4977 = inverseRoot[1]*R/512 mod q. Both scaled
        // products are <q*R for inputs <8q, giving final residues below 2q.
        // BEGIN GENERATED NORMALIZE
        for { let p := base } lt(p, add(base, 1024)) { p := add(p, 512) } {
            {
                let pa := add(p, 0)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 32)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 64)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 96)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 128)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 160)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 192)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 224)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 256)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 288)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 320)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 352)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 384)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 416)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 448)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
            {
                let pa := add(p, 480)
                let pt := add(pa, 1024)
                let u := mload(pa)
                let v := mload(pt)
                mstore(pa, mont(shl(7, add(u, v))))
                mstore(pt, mont(mul(sub(add(u, _Q4L32), v), 4977)))
            }
        }
        // END GENERATED NORMALIZE
    }
    return A;
}

/// @notice Convert native eight-lane products for the four-lane reference tests.
function expandProduct8(uint256[] memory A) pure returns (uint256[] memory B) {
    B = new uint256[](128);
    assembly ("memory-safe") {
        function expand4(x) -> r {
            x := and(or(x, shl(64, x)), _PAIR64)
            r := and(or(x, shl(32, x)), _M16L64)
        }
        let base := add(A, 32)
        let dst := add(B, 32)
        for { let w := 0 } lt(w, 64) { w := add(w, 1) } {
            let word := mload(add(base, shl(5, w)))
            mstore(add(dst, shl(6, w)), expand4(and(word, _L01)))
            mstore(add(add(dst, shl(6, w)), 32), expand4(shr(128, word)))
        }
    }
}
