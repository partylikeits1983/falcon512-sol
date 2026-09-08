// SPDX-License-Identifier: MIT
// FILE: FalconProduct.sol
// Product builders for the packed-SWAR NTT verifier path.
pragma solidity ^0.8.25;

import "./FalconNTT.sol";
import "./FalconNTTFused.sol";

function falcon_product_packed_calldata(uint256[] calldata s2, uint256[] calldata ntth)
    pure
    returns (uint256[] memory)
{
    return _unpackTo512(falcon_product_packed_words_calldata(s2, ntth));
}

function falcon_product_packed_words_calldata(uint256[] calldata s2, uint256[] calldata ntth)
    pure
    returns (uint256[] memory)
{
    return _nttInvPacked(_vecMulPacked(_nttFwPacked(_packFromCompactCalldata(s2)), _packFromCompactCalldata(ntth)));
}

/// @dev A nonzero flag also signals early rejection when the s2 norm alone
/// reaches the verifier's bound. Callers must check it before using product.
function falcon_product_packed_words_calldata_with_s2_norm(uint256[] calldata s2, uint256[] calldata ntth)
    pure
    returns (uint256[] memory product, uint256 norm, uint256 outOfRange)
{
    uint256[] memory packedS2;
    (packedS2, norm, outOfRange) = _packFromCompactCalldataWithNorm(s2);
    if (outOfRange != 0) return (product, norm, outOfRange);
    if (norm >= sigBound) return (product, norm, 1);
    product = falconProductFused(packedS2, ntth);
}
