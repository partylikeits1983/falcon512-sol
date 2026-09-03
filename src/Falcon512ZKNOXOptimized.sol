// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "./ZKNOX_falcon_utils.sol";
import "./ZKNOX_falcon_core_packed.sol";
import "./ZKNOX_shake_fast.sol";

/// @notice Prepared-input Falcon512 verifier based on ZKNOX/ETHFALCON's
/// helper-backed SHAKE256 and packed-SWAR NTT path.
///
/// This verifier expects prepared Falcon inputs. The caller provides:
/// - the original message bytes,
/// - the 40-byte Falcon salt,
/// - the decoded signature vector s2 compacted as 32 uint256 words,
/// - the public key already transformed to compacted NTT form.
contract Falcon512ZKNOXOptimized {
    bytes32 internal constant F1600_CODEHASH = 0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b;

    address public immutable f1600Helper;

    error BadHelper();

    constructor(address helper) {
        if (helper.codehash != F1600_CODEHASH) revert BadHelper();
        f1600Helper = helper;
    }

    function verifyPrepared(bytes calldata message, bytes calldata salt, uint256[] calldata s2, uint256[] calldata ntth)
        external
        view
        returns (bool)
    {
        if (salt.length != 40 || s2.length != falcon_S256 || ntth.length != falcon_S256) {
            return false;
        }

        (uint256[] memory product, uint256 norm, uint256 outOfRange) =
            falcon_product_packed_words_calldata_with_s2_norm(s2, ntth);
        if (outOfRange != 0) return false;

        address helper = f1600Helper;
        return verifyWithHashToPointNISTFastCalldataPackedProduct(salt, message, helper, product, norm);
    }
}
