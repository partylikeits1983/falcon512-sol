// SPDX-License-Identifier: MIT
// FILE: ZKNOX_falcon_core_packed.sol
// Product builders for the packed-SWAR NTT verifier path.
pragma solidity ^0.8.25;

import "./ZKNOX_NTT_falcon_packed.sol";

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

function falcon_product_packed_words_calldata_with_s2_norm(uint256[] calldata s2, uint256[] calldata ntth)
    pure
    returns (uint256[] memory product, uint256 norm, uint256 outOfRange)
{
    uint256[] memory packedS2;
    (packedS2, norm, outOfRange) = _packFromCompactCalldataWithNorm(s2);
    if (outOfRange != 0) return (product, norm, outOfRange);
    product = _nttInvPacked(_vecMulPacked(_nttFwPacked(packedS2), _packFromCompactCalldata(ntth)));
}
