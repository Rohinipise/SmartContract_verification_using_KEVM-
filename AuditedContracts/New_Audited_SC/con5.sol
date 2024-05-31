pragma solidity ^0.8.0;

contract Voting {
    mapping(address => bool) public hasVoted;
    uint256 public yesVotes;
    uint256 public noVotes;

    function vote(bool _vote) public {
        require(!hasVoted[msg.sender], "Already voted");
        hasVoted[msg.sender] = true;
        if (_vote) {
            yesVotes++;
        } else {
            noVotes++;
        }
    }
}
