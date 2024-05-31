pragma solidity ^0.8.0;

contract DigitalOwnership {
    address public owner;
    mapping(bytes32 => bool) public owned;

    constructor() {
        owner = msg.sender;
    }

    function claimOwnership(bytes32 _item) external {
        require(msg.sender == owner, "Only owner can claim ownership");
        require(!owned[_item], "Item already owned");
        owned[_item] = true;
    }
}
