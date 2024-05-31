pragma solidity ^0.8.0;

contract TokenVesting {
    address public beneficiary;
    uint256 public releaseTime;
    uint256 public amount;

    constructor(address _beneficiary, uint256 _releaseTime, uint256 _amount) {
        require(_releaseTime > block.timestamp, "Release time must be in the future");
        beneficiary = _beneficiary;
        releaseTime = _releaseTime;
        amount = _amount;
    }

    function release() external {
        require(block.timestamp >= releaseTime, "Release time not reached");
        payable(beneficiary).transfer(amount);
    }
}
