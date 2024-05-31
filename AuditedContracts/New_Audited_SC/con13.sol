pragma solidity ^0.8.0;

contract ProofOfOwnership {
    mapping(address => bytes32) public proofs;

    function storeProof(bytes32 _proof) external {
        proofs[msg.sender] = _proof;
    }

    function checkProof(address _user) external view returns (bytes32) {
        return proofs[_user];
    }
}
