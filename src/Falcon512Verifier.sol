// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import {Falcon} from "./FalconLegacy.sol";

/// @notice Falcon512 verifier with the canonical fixed-size encoding used by
/// the no-std Rust oracle in partylikeits1983/falcon512-stm32.
///
/// Signature encoding:
///   0x59 || 40-byte nonce || 625-byte padded compressed s
/// Public key encoding:
///   0x09 || 896-byte mod-q encoded h
contract Falcon512Verifier is Falcon {
    uint16 private constant SIG_LEN = 666;
    uint16 private constant PK_LEN = 897;
    uint8 private constant SIG_HEADER = 0x59;
    uint8 private constant PK_HEADER = 0x09;

    constructor(address tables_) Falcon(tables_) {}

    function verify(bytes calldata signature, bytes calldata publicKey, bytes calldata message)
        external
        view
        returns (bool)
    {
        if (signature.length != SIG_LEN || publicKey.length != PK_LEN) {
            return false;
        }
        if (uint8(signature[0]) != SIG_HEADER || uint8(publicKey[0]) != PK_HEADER) {
            return false;
        }
        if (message.length > 65535) {
            return false;
        }

        int16 rc = verifyLegacy(signature, message, publicKey);
        return rc == 0;
    }
}
