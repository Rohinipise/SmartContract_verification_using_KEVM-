// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProofOfExistence {
    mapping(bytes32 => bool) private proofs;

    event ProofAdded(bytes32 proof);

    function storeProof(bytes32 proof) public {
        proofs[proof] = true;
        emit ProofAdded(proof);
    }

    function checkProof(bytes32 proof) public view returns (bool) {
        return proofs[proof];
    }
}
