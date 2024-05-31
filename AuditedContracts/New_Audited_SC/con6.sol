pragma solidity ^0.8.0;

contract Voting {
    mapping(address => bool) public hasVoted;
    mapping(bytes32 => uint256) public voteCount;

    function vote(bytes32 _choice) external {
        require(!hasVoted[msg.sender], "Already voted");
        voteCount[_choice]++;
        hasVoted[msg.sender] = true;
    }

    function getVoteCount(bytes32 _choice) external view returns (uint256) {
        return voteCount[_choice];
    }
}
