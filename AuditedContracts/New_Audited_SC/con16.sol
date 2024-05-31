pragma solidity ^0.8.0;

contract ProofOfDelivery {
    mapping(bytes32 => bool) public deliveries;

    function deliver(bytes32 _shipmentId) external {
        deliveries[_shipmentId] = true;
    }

    function isDelivered(bytes32 _shipmentId) external view returns (bool) {
        return deliveries[_shipmentId];
    }
}
