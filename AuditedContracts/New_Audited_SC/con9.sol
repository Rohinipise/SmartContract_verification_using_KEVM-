pragma solidity ^0.8.0;

contract EscrowWithTimeLock {
    address public payer;
    address public payee;
    uint256 public amount;
    uint256 public releaseTime;
    bool public released;
    
    constructor(address _payer, address _payee, uint256 _releaseTime) {
        payer = _payer;
        payee = _payee;
        releaseTime = _releaseTime;
    }

    function deposit() external payable {
        require(msg.sender == payer, "Only payer can deposit");
        require(msg.value > 0, "Invalid amount");
        amount += msg.value;
    }

    function release() external {
        require(msg.sender == payee, "Only payee can release");
        require(!released && block.timestamp >= releaseTime, "Not yet released");
        payable(payee).transfer(amount);
        released = true;
    }
}
