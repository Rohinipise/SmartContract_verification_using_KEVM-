pragma solidity ^0.8.0;

contract MultiSigWallet {
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        payable(msg.sender).transfer(_amount);
    }

    function approve(address _spender, uint256 _amount) external {
        allowances[msg.sender][_spender] = _amount;
    }

    function transferFrom(address _from, address _to, uint256 _amount) external {
        require(allowances[_from][msg.sender] >= _amount, "Allowance exceeded");
        require(balances[_from] >= _amount, "Insufficient balance");
        allowances[_from][msg.sender] -= _amount;
        balances[_from] -= _amount;
        balances[_to] += _amount;
    }
}
