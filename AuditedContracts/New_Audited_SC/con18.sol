pragma solidity ^0.8.0;

contract DecentralizedIdentity {
    mapping(address => bytes32) public identities;

    function createIdentity(bytes32 _identity) external {
        require(identities[msg.sender] == 0x0, "Identity already exists");
        identities[msg.sender] = _identity;
    }

    function getIdentity(address _user) external view returns (bytes32) {
        return identities[_user];
    }
}
