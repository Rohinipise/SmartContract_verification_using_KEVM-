pragma solidity ^0.8.0;

contract DistributedStorage {
    mapping(uint256 => bytes) public data;

    function store(uint256 _key, bytes memory _value) external {
        data[_key] = _value;
    }

    function retrieve(uint256 _key) external view returns (bytes memory) {
        return data[_key];
    }
}
