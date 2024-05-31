pragma solidity ^0.8.0;

contract TokenVesting {
    address public beneficiary;
    uint256 public vestingStart;
    uint256 public vestingDuration;
    uint256 public vestingCliff;
    uint256 public released;

    constructor(address _beneficiary, uint256 _vestingDuration, uint256 _vestingCliff) {
        require(_vestingCliff <= _vestingDuration, "Cliff must be <= duration");
        beneficiary = _beneficiary;
        vestingDuration = _vestingDuration;
        vestingCliff = _vestingCliff;
        vestingStart = block.timestamp;
    }

    function release() external {
        require(block.timestamp >= vestingStart + vestingCliff, "Cliff not reached");
        uint256 vested = vestedAmount();
        require(vested > released, "No tokens to release");
        released = vested;
        // Transfer vested tokens to beneficiary
    }

    function vestedAmount() public view returns (uint256) {
        if (block.timestamp < vestingStart + vestingCliff) {
            return 0;
        } else if (block.timestamp >= vestingStart + vestingDuration) {
            return totalAmount();
        } else {
            return totalAmount() * (block.timestamp - vestingStart) / vestingDuration;
        }
    }

    function totalAmount() public view returns (uint256) {
        // Return total amount of tokens
    }
}
