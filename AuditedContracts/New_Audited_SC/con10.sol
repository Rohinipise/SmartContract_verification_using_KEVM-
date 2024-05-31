pragma solidity ^0.8.0;

contract Escrow {
    address public buyer;
    address public seller;
    uint256 public amount;

    constructor(address _buyer, address _seller, uint256 _amount) {
        buyer = _buyer;
        seller = _seller;
        amount = _amount;
    }

    function releaseToSeller() external {
        require(msg.sender == buyer, "Only buyer can release funds");
        payable(seller).transfer(amount);
    }

    function refundToBuyer() external {
        require(msg.sender == seller, "Only seller can refund funds");
        payable(buyer).transfer(amount);
    }
}
