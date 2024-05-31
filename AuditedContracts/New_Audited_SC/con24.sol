"// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

// A copy of https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ecc66719bd7681ed4eb8bf406f89a7408569ba9b/contracts/drafts/IERC20Permit.sol

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
interface IERC20Permit {
    /**
     * @dev Sets `amount` as the allowance of `spender` over `owner`'s tokens,
     * given `owner`'s signed approval.
     *
     * IMPORTANT: The same issues {IERC20-approve} has related to transaction
     * ordering also apply here.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     *
     * For more information on the signature format, see the
     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP
     * section].
     */
    function permit(address owner, address spender, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view returns (uint256);

    /**
     * @dev Returns the domain separator used in the encoding of the signature for `permit`, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import ""@openzeppelin/contracts/token/ERC20/ERC20.sol"";
import ""@openzeppelin/contracts/utils/Counters.sol"";
import ""./IERC20Permit.sol"";
import ""./ECDSA.sol"";
import ""./EIP712.sol"";

// An adapted copy of https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ecc66719bd7681ed4eb8bf406f89a7408569ba9b/contracts/drafts/ERC20Permit.sol

/**
 * @dev Implementation of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
abstract contract ERC20Permit is ERC20, IERC20Permit, EIP712 {
    using Counters for Counters.Counter;

    mapping (address => Counters.Counter) private _nonces;

    // solhint-disable-next-line var-name-mixedcase
    bytes32 private immutable _PERMIT_TYPEHASH = keccak256(""Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"");

    /**
     * @dev See {IERC20Permit-permit}.
     */
    function permit(address owner, address spender, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual override {
        // solhint-disable-next-line not-rely-on-time
        require(block.timestamp <= deadline, ""ERC20Permit: expired deadline"");

        bytes32 structHash = keccak256(
            abi.encode(
                _PERMIT_TYPEHASH,
                owner,
                spender,
                amount,
                _nonces[owner].current(),
                deadline
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, ""ERC20Permit: invalid signature"");

        _nonces[owner].increment();
        // SWC-Transaction Order Dependence: L53
        _approve(owner, spender, amount);
    }

    /**
     * @dev See {IERC20Permit-nonces}.
     */
    function nonces(address owner) public view override returns (uint256) {
        return _nonces[owner].current();
    }

    /**
     * @dev See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
}
// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

// A copy of https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ecc66719bd7681ed4eb8bf406f89a7408569ba9b/contracts/cryptography/ECDSA.sol

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert(""ECDSA: invalid signature length"");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return recover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover-bytes32-bytes-} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, ""ECDSA: invalid signature s value"");
        require(v == 27 || v == 28, ""ECDSA: invalid signature v value"");

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), ""ECDSA: invalid signature"");

        return signer;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * replicates the behavior of the
     * https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign[`eth_sign`]
     * JSON-RPC method.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked(""\x19Ethereum Signed Message:\n32"", hash));
    }
}
// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

// A copy of https://github.com/OpenZeppelin/openzeppelin-contracts/blob/ecc66719bd7681ed4eb8bf406f89a7408569ba9b/contracts/drafts/EIP712.sol

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,
 * thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding
 * they need in their contracts using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
 * ({_hashTypedDataV4}).
 *
 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating
 * the chain id to protect against replay attacks on an eventual fork of the chain.
 *
 * NOTE: This contract implements the version of the encoding known as ""v4"", as implemented by the JSON RPC method
 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
 */
abstract contract EIP712 {
    /* solhint-disable var-name-mixedcase */
    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;
    /* solhint-enable var-name-mixedcase */

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name, string memory version) internal {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash = keccak256(""EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"");
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = _getChainId();
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(typeHash, hashedName, hashedVersion);
        _TYPE_HASH = typeHash;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (_getChainId() == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }

    function _buildDomainSeparator(bytes32 typeHash, bytes32 name, bytes32 version) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                typeHash,
                name,
                version,
                _getChainId(),
                address(this)
            )
        );
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256(""Mail(address to,string contents)""),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(""\x19\x01"", _domainSeparatorV4(), structHash));
    }

    function _getChainId() private pure returns (uint256 chainId) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            chainId := chainid()
        }
    }
}
// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

import ""@openzeppelin/contracts/token/ERC20/ERC20Burnable.sol"";
import ""@openzeppelin/contracts/access/Ownable.sol"";
import ""./ERC20Permit.sol"";


contract OneInch is ERC20Permit, ERC20Burnable, Ownable {
    constructor(address _owner) public ERC20(""1INCH Token"", ""1INCH"") EIP712(""1INCH Token"", ""1"") {
        _mint(_owner, 1.5e9 ether);
        transferOwnership(_owner);
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}
"
"// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.3;

import {ERC20} from ""@openzeppelin/contracts/token/ERC20/ERC20.sol"";
import {SafeERC20} from ""./libs/SafeERC20.sol"";
import {
    ReentrancyGuardUpgradeable
} from ""@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol"";
import {
    AddressUpgradeable
} from ""@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol"";
import {
    OwnableUpgradeable
} from ""@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol"";
import {
    MulticallUpgradeable
} from ""@openzeppelin/contracts-upgradeable/utils/MulticallUpgradeable.sol"";
import {MoneyMarket} from ""./moneymarkets/MoneyMarket.sol"";
import {IFeeModel} from ""./models/fee/IFeeModel.sol"";
import {IInterestModel} from ""./models/interest/IInterestModel.sol"";
import {NFT} from ""./tokens/NFT.sol"";
import {FundingMultitoken} from ""./tokens/FundingMultitoken.sol"";
import {MPHMinter} from ""./rewards/MPHMinter.sol"";
import {IInterestOracle} from ""./models/interest-oracle/IInterestOracle.sol"";
import {DecMath} from ""./libs/DecMath.sol"";
import {Rescuable} from ""./libs/Rescuable.sol"";
import {Sponsorable} from ""./libs/Sponsorable.sol"";
import {console} from ""hardhat/console.sol"";

/**
    @title DeLorean Interest -- It's coming back from the future!
    @author Zefram Lou
    @notice The main pool contract for fixed-rate deposits
    @dev The contract to interact with for most actions
 */
contract DInterest is
    ReentrancyGuardUpgradeable,
    OwnableUpgradeable,
    Rescuable,
    MulticallUpgradeable,
    Sponsorable
{
    using SafeERC20 for ERC20;
    using AddressUpgradeable for address;
    using DecMath for uint256;

    // Constants
    uint256 internal constant PRECISION = 10**18;
    /**
        @dev used for sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex
     */
    uint256 internal constant EXTRA_PRECISION = 10**27;
    /**
        @dev used for funding.principalPerToken
     */
    uint256 internal constant ULTRA_PRECISION = 2**128;
    /**
        @dev Specifies the threshold for paying out funder interests
     */
    uint256 internal constant FUNDER_PAYOUT_THRESHOLD_DIVISOR = 10**10;

    // User deposit data
    // Each deposit has an ID used in the depositNFT, which is equal to its index in `deposits` plus 1
    struct Deposit {
        uint256 virtualTokenTotalSupply; // depositAmount + interestAmount, behaves like a zero coupon bond
        uint256 interestRate; // interestAmount = interestRate * depositAmount
        uint256 feeRate; // feeAmount = feeRate * depositAmount
        uint256 averageRecordedIncomeIndex; // Average income index at time of deposit, used for computing deposit surplus
        uint64 maturationTimestamp; // Unix timestamp after which the deposit may be withdrawn, in seconds
        uint64 fundingID; // The ID of the associated Funding struct. 0 if not funded.
    }
    Deposit[] internal deposits;

    // Funding data
    // Each funding has an ID used in the fundingMultitoken, which is equal to its index in `fundingList` plus 1
    struct Funding {
        uint64 depositID; // The ID of the associated Deposit struct.
        uint64 lastInterestPayoutTimestamp; // Unix timestamp of the most recent interest payout, in seconds
        uint256 recordedMoneyMarketIncomeIndex; // the income index at the last update (creation or withdrawal)
        uint256 principalPerToken; // The amount of stablecoins that's earning interest for you per funding token you own. Scaled to 18 decimals regardless of stablecoin decimals.
    }
    Funding[] internal fundingList;
    // the sum of (recordedFundedPrincipalAmount / recordedMoneyMarketIncomeIndex) of all fundings
    uint256 public sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex;

    // Params
    /**
        @dev Maximum deposit period, in seconds
     */
    uint64 public MaxDepositPeriod;
    /**
        @dev Minimum deposit amount, in stablecoins
     */
    uint256 public MinDepositAmount;

    // Global variables
    uint256 public totalDeposit;
    uint256 public totalInterestOwed;
    uint256 public totalFeeOwed;
    uint256 public totalFundedPrincipalAmount;

    // External smart contracts
    MoneyMarket public moneyMarket;
    ERC20 public stablecoin;
    IFeeModel public feeModel;
    IInterestModel public interestModel;
    IInterestOracle public interestOracle;
    NFT public depositNFT;
    FundingMultitoken public fundingMultitoken;
    MPHMinter public mphMinter;

    // Extra params
    /**
        @dev The maximum amount of deposit in the pool. Set to 0 to disable the cap.
     */
    uint256 public GlobalDepositCap;

    // Events
    event EDeposit(
        address indexed sender,
        uint256 indexed depositID,
        uint256 depositAmount,
        uint256 interestAmount,
        uint256 feeAmount,
        uint64 maturationTimestamp
    );
    event ETopupDeposit(
        address indexed sender,
        uint64 indexed depositID,
        uint256 depositAmount,
        uint256 interestAmount,
        uint256 feeAmount
    );
    event ERolloverDeposit(
        address indexed sender,
        uint64 indexed depositID,
        uint64 indexed newDepositID
    );
    event EWithdraw(
        address indexed sender,
        uint256 indexed depositID,
        bool indexed early,
        uint256 virtualTokenAmount,
        uint256 feeAmount
    );
    event EFund(
        address indexed sender,
        uint64 indexed fundingID,
        uint256 fundAmount,
        uint256 tokenAmount
    );
    event EPayFundingInterest(
        uint256 indexed fundingID,
        uint256 interestAmount,
        uint256 refundAmount
    );
    event ESetParamAddress(
        address indexed sender,
        string indexed paramName,
        address newValue
    );
    event ESetParamUint(
        address indexed sender,
        string indexed paramName,
        uint256 newValue
    );

    function __DInterest_init(
        uint64 _MaxDepositPeriod,
        uint256 _MinDepositAmount,
        address _moneyMarket,
        address _stablecoin,
        address _feeModel,
        address _interestModel,
        address _interestOracle,
        address _depositNFT,
        address _fundingMultitoken,
        address _mphMinter
    ) internal initializer {
        __ReentrancyGuard_init();
        __Ownable_init();

        moneyMarket = MoneyMarket(_moneyMarket);
        stablecoin = ERC20(_stablecoin);
        feeModel = IFeeModel(_feeModel);
        interestModel = IInterestModel(_interestModel);
        interestOracle = IInterestOracle(_interestOracle);
        depositNFT = NFT(_depositNFT);
        fundingMultitoken = FundingMultitoken(_fundingMultitoken);
        mphMinter = MPHMinter(_mphMinter);
        MaxDepositPeriod = _MaxDepositPeriod;
        MinDepositAmount = _MinDepositAmount;
    }

    /**
        @param _MaxDepositPeriod The maximum deposit period, in seconds
        @param _MinDepositAmount The minimum deposit amount, in stablecoins
        @param _moneyMarket Address of MoneyMarket that's used for generating interest (owner must be set to this DInterest contract)
        @param _stablecoin Address of the stablecoin used to store funds
        @param _feeModel Address of the FeeModel contract that determines how fees are charged
        @param _interestModel Address of the InterestModel contract that determines how much interest to offer
        @param _interestOracle Address of the InterestOracle contract that provides the average interest rate
        @param _depositNFT Address of the NFT representing ownership of deposits (owner must be set to this DInterest contract)
        @param _fundingMultitoken Address of the ERC1155 multitoken representing ownership of fundings (this DInterest contract must have the minter-burner role)
        @param _mphMinter Address of the contract for handling minting MPH to users
     */
    function initialize(
        uint64 _MaxDepositPeriod,
        uint256 _MinDepositAmount,
        address _moneyMarket,
        address _stablecoin,
        address _feeModel,
        address _interestModel,
        address _interestOracle,
        address _depositNFT,
        address _fundingMultitoken,
        address _mphMinter
    ) external virtual initializer {
        __DInterest_init(
            _MaxDepositPeriod,
            _MinDepositAmount,
            _moneyMarket,
            _stablecoin,
            _feeModel,
            _interestModel,
            _interestOracle,
            _depositNFT,
            _fundingMultitoken,
            _mphMinter
        );
    }

    /**
        Public action functions
     */

    /**
        @notice Create a deposit using `depositAmount` stablecoin that matures at timestamp `maturationTimestamp`.
        @dev The ERC-721 NFT representing deposit ownership is given to msg.sender
        @param depositAmount The amount of deposit, in stablecoin
        @param maturationTimestamp The Unix timestamp of maturation, in seconds
        @return depositID The ID of the created deposit
        @return interestAmount The amount of fixed-rate interest
     */
    function deposit(uint256 depositAmount, uint64 maturationTimestamp)
        external
        nonReentrant
        returns (uint64 depositID, uint256 interestAmount)
    {
        return _deposit(msg.sender, depositAmount, maturationTimestamp, false);
    }

    /**
        @notice Add `depositAmount` stablecoin to the existing deposit with ID `depositID`.
        @dev The interest rate for the topped up funds will be the current oracle rate.
        @param depositID The deposit to top up
        @param depositAmount The amount to top up, in stablecoin
        @return interestAmount The amount of interest that will be earned by the topped up funds at maturation
     */
    function topupDeposit(uint64 depositID, uint256 depositAmount)
        external
        nonReentrant
        returns (uint256 interestAmount)
    {
        return _topupDeposit(msg.sender, depositID, depositAmount);
    }

    /**
        @notice Withdraw all funds from deposit with ID `depositID` and use them
                to create a new deposit that matures at time `maturationTimestamp`
        @param depositID The deposit to roll over
        @param maturationTimestamp The Unix timestamp of the new deposit, in seconds
        @return newDepositID The ID of the new deposit
     */
    function rolloverDeposit(uint64 depositID, uint64 maturationTimestamp)
        external
        nonReentrant
        returns (uint256 newDepositID, uint256 interestAmount)
    {
        return _rolloverDeposit(msg.sender, depositID, maturationTimestamp);
    }

    /**
        @notice Withdraws funds from the deposit with ID `depositID`.
        @dev Virtual tokens behave like zero coupon bonds, after maturation withdrawing 1 virtual token
             yields 1 stablecoin. The total supply is given by deposit.virtualTokenTotalSupply
        @param depositID the deposit to withdraw from
        @param virtualTokenAmount the amount of virtual tokens to withdraw
        @param early True if intend to withdraw before maturation, false otherwise
        @return withdrawnStablecoinAmount the amount of stablecoins withdrawn
     */
    function withdraw(
        uint64 depositID,
        uint256 virtualTokenAmount,
        bool early
    ) external nonReentrant returns (uint256 withdrawnStablecoinAmount) {
        return
            _withdraw(msg.sender, depositID, virtualTokenAmount, early, false);
    }

    /**
        @notice Funds the fixed-rate interest of the deposit with ID `depositID`.
                In exchange, the funder receives the future floating-rate interest
                generated by the portion of the deposit whose interest was funded.
        @dev The sender receives ERC-1155 multitokens (fundingMultitoken) representing
             their floating-rate bonds.
        @param depositID The deposit whose fixed-rate interest will be funded
        @param fundAmount The amount of fixed-rate interest to fund.
                          If it exceeds surplusOfDeposit(depositID), it will be set to
                          the surplus value instead.
        @param fundingID The ID of the fundingMultitoken the sender received
     */
    function fund(uint64 depositID, uint256 fundAmount)
        external
        nonReentrant
        returns (uint64 fundingID)
    {
        return _fund(msg.sender, depositID, fundAmount);
    }

    /**
        @notice Distributes the floating-rate interest accrued by a deposit to the
                floating-rate bond holders.
        @param fundingID The ID of the floating-rate bond
        @return interestAmount The amount of interest distributed, in stablecoins
     */
    function payInterestToFunders(uint64 fundingID)
        external
        nonReentrant
        returns (uint256 interestAmount)
    {
        return _payInterestToFunders(fundingID, moneyMarket.incomeIndex());
    }

    /**
        Sponsored action functions
     */

    function sponsoredDeposit(
        uint256 depositAmount,
        uint64 maturationTimestamp,
        Sponsorship calldata sponsorship
    )
        external
        nonReentrant
        sponsored(
            sponsorship,
            this.sponsoredDeposit.selector,
            abi.encode(depositAmount, maturationTimestamp)
        )
        returns (uint64 depositID, uint256 interestAmount)
    {
        return
            _deposit(
                sponsorship.sender,
                depositAmount,
                maturationTimestamp,
                false
            );
    }

    function sponsoredTopupDeposit(
        uint64 depositID,
        uint256 depositAmount,
        Sponsorship calldata sponsorship
    )
        external
        nonReentrant
        sponsored(
            sponsorship,
            this.sponsoredTopupDeposit.selector,
            abi.encode(depositID, depositAmount)
        )
        returns (uint256 interestAmount)
    {
        return _topupDeposit(sponsorship.sender, depositID, depositAmount);
    }

    function sponsoredRolloverDeposit(
        uint64 depositID,
        uint64 maturationTimestamp,
        Sponsorship calldata sponsorship
    )
        external
        nonReentrant
        sponsored(
            sponsorship,
            this.sponsoredRolloverDeposit.selector,
            abi.encode(depositID, maturationTimestamp)
        )
        returns (uint256 newDepositID, uint256 interestAmount)
    {
        return
            _rolloverDeposit(
                sponsorship.sender,
                depositID,
                maturationTimestamp
            );
    }

    function sponsoredWithdraw(
        uint64 depositID,
        uint256 virtualTokenAmount,
        bool early,
        Sponsorship calldata sponsorship
    )
        external
        nonReentrant
        sponsored(
            sponsorship,
            this.sponsoredWithdraw.selector,
            abi.encode(depositID, virtualTokenAmount, early)
        )
        returns (uint256 withdrawnStablecoinAmount)
    {
        return
            _withdraw(
                sponsorship.sender,
                depositID,
                virtualTokenAmount,
                early,
                false
            );
    }

    function sponsoredFund(
        uint64 depositID,
        uint256 fundAmount,
        Sponsorship calldata sponsorship
    )
        external
        nonReentrant
        sponsored(
            sponsorship,
            this.sponsoredFund.selector,
            abi.encode(depositID, fundAmount)
        )
        returns (uint64 fundingID)
    {
        return _fund(sponsorship.sender, depositID, fundAmount);
    }

    /**
        Public getter functions
     */

    /**
        @notice Computes the amount of fixed-rate interest (before fees) that
                will be given to a deposit of `depositAmount` stablecoins that
                matures in `depositPeriodInSeconds` seconds.
        @param depositAmount The deposit amount, in stablecoins
        @param depositPeriodInSeconds The deposit period, in seconds
        @return interestAmount The amount of fixed-rate interest (before fees)
     */
    function calculateInterestAmount(
        uint256 depositAmount,
        uint256 depositPeriodInSeconds
    ) public virtual returns (uint256 interestAmount) {
        (, uint256 moneyMarketInterestRatePerSecond) =
            interestOracle.updateAndQuery();
        (bool surplusIsNegative, uint256 surplusAmount) = surplus();

        return
            interestModel.calculateInterestAmount(
                depositAmount,
                depositPeriodInSeconds,
                moneyMarketInterestRatePerSecond,
                surplusIsNegative,
                surplusAmount
            );
    }

    /**
        @notice Computes the pool's overall surplus, which is the value of its holdings
                in the `moneyMarket` minus the amount owed to depositors, funders, and
                the fee beneficiary.
        @return isNegative True if the surplus is negative, false otherwise
        @return surplusAmount The absolute value of the surplus, in stablecoins
     */
    function surplus()
        public
        virtual
        returns (bool isNegative, uint256 surplusAmount)
    {
        return _surplus(moneyMarket.incomeIndex());
    }

    /**
        @notice Computes the raw surplus of a deposit, which is the current value of the
                deposit in the money market minus the amount owed (deposit + interest + fee).
                The deposit's funding status is not considered here, meaning even if a deposit's
                fixed-rate interest is fully funded, it likely will still have a non-zero surplus.
        @param depositID The ID of the deposit
        @return isNegative True if the surplus is negative, false otherwise
        @return surplusAmount The absolute value of the surplus, in stablecoins
     */
    function rawSurplusOfDeposit(uint64 depositID)
        public
        virtual
        returns (bool isNegative, uint256 surplusAmount)
    {
        return _rawSurplusOfDeposit(depositID, moneyMarket.incomeIndex());
    }

    /**
        @notice Returns the total number of deposits.
        @return deposits.length
     */
    function depositsLength() external view returns (uint256) {
        return deposits.length;
    }

    /**
        @notice Returns the total number of floating-rate bonds.
        @return fundingList.length
     */
    function fundingListLength() external view returns (uint256) {
        return fundingList.length;
    }

    /**
        @notice Returns the Deposit struct associated with the deposit with ID
                `depositID`.
        @param depositID The ID of the deposit
        @return The deposit struct
     */
    function getDeposit(uint64 depositID)
        external
        view
        returns (Deposit memory)
    {
        return deposits[depositID - 1];
    }

    /**
        @notice Returns the Funding struct associated with the floating-rate bond with ID
                `fundingID`.
        @param fundingID The ID of the floating-rate bond
        @return The Funding struct
     */
    function getFunding(uint64 fundingID)
        external
        view
        returns (Funding memory)
    {
        return fundingList[fundingID - 1];
    }

    /**
        Internal action functions
     */

    /**
        @dev See {deposit}
     */
    function _deposit(
        address sender,
        uint256 depositAmount,
        uint64 maturationTimestamp,
        bool rollover
    ) internal virtual returns (uint64 depositID, uint256 interestAmount) {
        (depositID, interestAmount) = _depositRecordData(
            sender,
            depositAmount,
            maturationTimestamp
        );
        _depositTransferFunds(sender, depositAmount, rollover);
    }

    function _depositRecordData(
        address sender,
        uint256 depositAmount,
        uint64 maturationTimestamp
    ) internal virtual returns (uint64 depositID, uint256 interestAmount) {
        // Ensure input is valid
        require(depositAmount >= MinDepositAmount, ""BAD_AMOUNT"");
        uint256 depositPeriod = maturationTimestamp - block.timestamp;
        require(depositPeriod <= MaxDepositPeriod, ""BAD_TIME"");

        // Calculate interest
        interestAmount = calculateInterestAmount(depositAmount, depositPeriod);
        require(interestAmount > 0, ""BAD_INTEREST"");

        // Calculate fee
        uint256 feeAmount =
            feeModel.getInterestFeeAmount(address(this), interestAmount);
        interestAmount -= feeAmount;

        // Record deposit data
        deposits.push(
            Deposit({
                virtualTokenTotalSupply: depositAmount + interestAmount,
                interestRate: interestAmount.decdiv(depositAmount),
                feeRate: feeAmount.decdiv(depositAmount),
                maturationTimestamp: maturationTimestamp,
                fundingID: 0,
                averageRecordedIncomeIndex: moneyMarket.incomeIndex()
            })
        );
        require(deposits.length <= type(uint64).max, ""OVERFLOW"");
        depositID = uint64(deposits.length);

        // Update global values
        totalDeposit += depositAmount;
        {
            uint256 depositCap = GlobalDepositCap;
            require(depositCap == 0 || totalDeposit <= depositCap, ""CAP"");
        }
        totalInterestOwed += interestAmount;
        totalFeeOwed += feeAmount;

        // Mint depositNFT
        depositNFT.mint(sender, depositID);

        // Emit event
        emit EDeposit(
            sender,
            depositID,
            depositAmount,
            interestAmount,
            feeAmount,
            maturationTimestamp
        );

        // Vest MPH to sender
        mphMinter.createVestForDeposit(sender, depositID);
    }

    function _depositTransferFunds(
        address sender,
        uint256 depositAmount,
        bool rollover
    ) internal virtual {
        // Only transfer funds from sender if it's not a rollover
        // because if it is the funds are already in the contract
        if (!rollover) {
            // Transfer `depositAmount` stablecoin to DInterest
            stablecoin.safeTransferFrom(sender, address(this), depositAmount);

            // Lend `depositAmount` stablecoin to money market
            stablecoin.safeApprove(address(moneyMarket), depositAmount);
            moneyMarket.deposit(depositAmount);
        }
    }

    /**
        @dev See {topupDeposit}
     */
    function _topupDeposit(
        address sender,
        uint64 depositID,
        uint256 depositAmount
    ) internal virtual returns (uint256 interestAmount) {
        interestAmount = _topupDepositRecordData(
            sender,
            depositID,
            depositAmount
        );
        _topupDepositTransferFunds(sender, depositAmount);
    }

    function _topupDepositRecordData(
        address sender,
        uint64 depositID,
        uint256 depositAmount
    ) internal virtual returns (uint256 interestAmount) {
        Deposit storage depositEntry = _getDeposit(depositID);
        require(depositNFT.ownerOf(depositID) == sender, ""NOT_OWNER"");

        // underflow check prevents topups after maturation
        uint256 depositPeriod =
            depositEntry.maturationTimestamp - block.timestamp;

        // Calculate interest
        interestAmount = calculateInterestAmount(depositAmount, depositPeriod);
        require(interestAmount > 0, ""BAD_INTEREST"");

        // Calculate fee
        uint256 feeAmount =
            feeModel.getInterestFeeAmount(address(this), interestAmount);
        interestAmount -= feeAmount;

        // Update deposit struct
        uint256 interestRate = depositEntry.interestRate;
        uint256 currentDepositAmount =
            depositEntry.virtualTokenTotalSupply.decdiv(
                interestRate + PRECISION
            );
        depositEntry.virtualTokenTotalSupply += depositAmount + interestAmount;
        depositEntry.interestRate =
            (PRECISION * interestAmount + currentDepositAmount * interestRate) /
            (depositAmount + currentDepositAmount);
        depositEntry.feeRate =
            (PRECISION *
                feeAmount +
                currentDepositAmount *
                depositEntry.feeRate) /
            (depositAmount + currentDepositAmount);
        uint256 sumOfRecordedDepositAmountDivRecordedIncomeIndex =
            (currentDepositAmount * EXTRA_PRECISION) /
                depositEntry.averageRecordedIncomeIndex +
                (depositAmount * EXTRA_PRECISION) /
                moneyMarket.incomeIndex();
        depositEntry.averageRecordedIncomeIndex =
            ((depositAmount + currentDepositAmount) * EXTRA_PRECISION) /
            sumOfRecordedDepositAmountDivRecordedIncomeIndex;

        // Update global values
        totalDeposit += depositAmount;
        {
            uint256 depositCap = GlobalDepositCap;
            require(depositCap == 0 || totalDeposit <= depositCap, ""CAP"");
        }
        totalInterestOwed += interestAmount;
        totalFeeOwed += feeAmount;

        // Emit event
        emit ETopupDeposit(
            sender,
            depositID,
            depositAmount,
            interestAmount,
            feeAmount
        );

        // Update vest
        mphMinter.updateVestForDeposit(
            depositID,
            currentDepositAmount,
            depositAmount
        );
    }

    function _topupDepositTransferFunds(address sender, uint256 depositAmount)
        internal
        virtual
    {
        // Transfer `depositAmount` stablecoin to DInterest
        stablecoin.safeTransferFrom(sender, address(this), depositAmount);

        // Lend `depositAmount` stablecoin to money market
        stablecoin.safeApprove(address(moneyMarket), depositAmount);
        moneyMarket.deposit(depositAmount);
    }

    /**
        @dev See {rolloverDeposit}
     */
    function _rolloverDeposit(
        address sender,
        uint64 depositID,
        uint64 maturationTimestamp
    ) internal virtual returns (uint64 newDepositID, uint256 interestAmount) {
        // withdraw from existing deposit
        uint256 withdrawnStablecoinAmount =
            _withdraw(sender, depositID, type(uint256).max, false, true);

        // deposit funds into a new deposit
        (newDepositID, interestAmount) = _deposit(
            sender,
            withdrawnStablecoinAmount,
            maturationTimestamp,
            true
        );

        emit ERolloverDeposit(sender, depositID, newDepositID);
    }

    /**
        @dev See {withdraw}
        @param rollover True if being called from {_rolloverDeposit}, false otherwise
     */
    function _withdraw(
        address sender,
        uint64 depositID,
        uint256 virtualTokenAmount,
        bool early,
        bool rollover
    ) internal virtual returns (uint256 withdrawnStablecoinAmount) {
        (
            uint256 withdrawAmount,
            uint256 feeAmount,
            uint256 fundingInterestAmount,
            uint256 refundAmount
        ) = _withdrawRecordData(sender, depositID, virtualTokenAmount, early);
        return
            _withdrawTransferFunds(
                sender,
                _getDeposit(depositID).fundingID,
                withdrawAmount,
                feeAmount,
                fundingInterestAmount,
                refundAmount,
                rollover
            );
    }

    function _withdrawRecordData(
        address sender,
        uint64 depositID,
        uint256 virtualTokenAmount,
        bool early
    )
        internal
        virtual
        returns (
            uint256 withdrawAmount,
            uint256 feeAmount,
            uint256 fundingInterestAmount,
            uint256 refundAmount
        )
    {
        // Verify input
        require(virtualTokenAmount > 0, ""BAD_AMOUNT"");
        Deposit storage depositEntry = _getDeposit(depositID);
        if (early) {
            require(
                block.timestamp < depositEntry.maturationTimestamp,
                ""MATURE""
            );
        } else {
            require(
                block.timestamp >= depositEntry.maturationTimestamp,
                ""IMMATURE""
            );
        }
        require(depositNFT.ownerOf(depositID) == sender, ""NOT_OWNER"");

        // Check if withdrawing all funds
        {
            uint256 virtualTokenTotalSupply =
                depositEntry.virtualTokenTotalSupply;
            if (virtualTokenAmount > virtualTokenTotalSupply) {
                virtualTokenAmount = virtualTokenTotalSupply;
            }
        }

        // Compute token amounts
        uint256 interestRate = depositEntry.interestRate;
        uint256 feeRate = depositEntry.feeRate;
        uint256 depositAmount =
            virtualTokenAmount.decdiv(interestRate + PRECISION);
        {
            uint256 interestAmount =
                early ? 0 : virtualTokenAmount - depositAmount;
            withdrawAmount = depositAmount + interestAmount;
        }
        if (early) {
            // apply fee to withdrawAmount
            uint256 earlyWithdrawFee =
                feeModel.getEarlyWithdrawFeeAmount(
                    address(this),
                    depositID,
                    withdrawAmount
                );
            feeAmount = earlyWithdrawFee;
            withdrawAmount -= earlyWithdrawFee;
        } else {
            feeAmount = depositAmount.decmul(feeRate);
        }

        // Update global values
        totalDeposit -= depositAmount;
        totalInterestOwed -= virtualTokenAmount - depositAmount;
        totalFeeOwed -= depositAmount.decmul(feeRate);

        // If deposit was funded, compute funding interest payout
        uint64 fundingID = depositEntry.fundingID;
        if (fundingID > 0) {
            Funding storage funding = _getFunding(fundingID);

            // Compute funded deposit amount before withdrawal
            uint256 recordedFundedPrincipalAmount =
                (fundingMultitoken.totalSupply(fundingID) *
                    funding.principalPerToken) / ULTRA_PRECISION;

            // Shrink funding principal per token value
            {
                uint256 totalPrincipal =
                    _depositVirtualTokenToPrincipal(
                        depositID,
                        depositEntry.virtualTokenTotalSupply
                    );
                uint256 totalPrincipalDecrease =
                    virtualTokenAmount + depositAmount.decmul(feeRate);
                if (
                    totalPrincipal <=
                    totalPrincipalDecrease + recordedFundedPrincipalAmount
                ) {
                    // Not enough unfunded principal, need to decrease funding principal per token value
                    funding.principalPerToken = (totalPrincipal >=
                        totalPrincipalDecrease)
                        ? (funding.principalPerToken *
                            (totalPrincipal - totalPrincipalDecrease)) /
                            recordedFundedPrincipalAmount
                        : 0;
                }
            }

            // Compute interest payout + refund
            // and update relevant state
            (
                fundingInterestAmount,
                refundAmount
            ) = _computeAndUpdateFundingInterestAfterWithdraw(
                fundingID,
                recordedFundedPrincipalAmount,
                early
            );
        }

        // Update vest
        {
            uint256 depositAmountBeforeWithdrawal =
                _getDeposit(depositID).virtualTokenTotalSupply.decdiv(
                    interestRate + PRECISION
                );
            mphMinter.updateVestForDeposit(
                depositID,
                depositAmountBeforeWithdrawal,
                0
            );
        }

        // Burn `virtualTokenAmount` deposit virtual tokens
        _getDeposit(depositID).virtualTokenTotalSupply -= virtualTokenAmount;

        // Emit event
        emit EWithdraw(sender, depositID, early, virtualTokenAmount, feeAmount);
    }

    function _withdrawTransferFunds(
        address sender,
        uint64 fundingID,
        uint256 withdrawAmount,
        uint256 feeAmount,
        uint256 fundingInterestAmount,
        uint256 refundAmount,
        bool rollover
    ) internal virtual returns (uint256 withdrawnStablecoinAmount) {
        // Withdraw funds from money market
        // Withdraws principal together with funding interest to save gas
        if (rollover) {
        "
    // Rollover mode

            // We do this because feePlusFundingInterest might
            // be slightly less due to rounding
            uint256 feePlusFundingInterest =
                moneyMarket.withdraw(feeAmount + fundingInterestAmount);
            if (feePlusFundingInterest >= feeAmount + fundingInterestAmount) {
                // enough to pay everything
                feeAmount = feePlusFundingInterest - fundingInterestAmount;
            } else if (feePlusFundingInterest >= feeAmount) {
                // enough to pay fee
                fundingInterestAmount = feePlusFundingInterest - feeAmount;
            } else {
                // not enough to pay fee
                feeAmount = feePlusFundingInterest;
                fundingInterestAmount = 0;
            }

            // we're keeping the withdrawal amount in the money market
            withdrawnStablecoinAmount = withdrawAmount;
        } else {
            uint256 actualWithdrawnAmount =
                moneyMarket.withdraw(
                    withdrawAmount + feeAmount + fundingInterestAmount
                );

            // We do this because `actualWithdrawnAmount` might
            // be slightly less due to rounding
            withdrawnStablecoinAmount = withdrawAmount;
            if (
                actualWithdrawnAmount >=
                withdrawAmount + feeAmount + fundingInterestAmount
            ) {
                // enough to pay everything
                feeAmount =
                    actualWithdrawnAmount -
                    withdrawAmount -
                    fundingInterestAmount;
            } else if (actualWithdrawnAmount >= withdrawAmount + feeAmount) {
                // enough to pay withdrawal + fee + remainder
                // give remainder to funding interest
                fundingInterestAmount =
                    actualWithdrawnAmount -
                    withdrawAmount -
                    feeAmount;
            } else if (actualWithdrawnAmount >= withdrawAmount) {
                // enough to pay withdrawal + remainder
                // give remainder to fee
                feeAmount = actualWithdrawnAmount - withdrawAmount;
                fundingInterestAmount = 0;
            } else {
                // not enough to pay withdrawal
                // give everything to withdrawal
                withdrawnStablecoinAmount = actualWithdrawnAmount;
                feeAmount = 0;
                fundingInterestAmount = 0;
            }

            if (withdrawnStablecoinAmount > 0) {
                stablecoin.safeTransfer(sender
            }
        }

        // Send `feeAmount` stablecoin to feeModel beneficiary
        if (feeAmount > 0) {
            stablecoin.safeTransfer(feeModel.beneficiary()
        }

        // Distribute `fundingInterestAmount` stablecoins to funders
        if (fundingInterestAmount > 0) {
            stablecoin.safeApprove(
                address(fundingMultitoken)
                fundingInterestAmount
            );
            fundingMultitoken.distributeDividends(
                fundingID
                address(stablecoin)
                fundingInterestAmount
            );
            // Mint funder rewards
            if (fundingInterestAmount > refundAmount) {
                _distributeFundingRewards(
                    fundingID
                    fundingInterestAmount - refundAmount
                );
            }
        }
    }

    /**
        @dev See {fund}
     */
    function _fund(
        address sender
        uint64 depositID
        uint256 fundAmount
    ) internal virtual returns (uint64 fundingID) {
        uint256 actualFundAmount;
        (fundingID
            sender
            depositID
            fundAmount
        );
        _fundTransferFunds(sender
    }

    function _fundRecordData(
        address sender
        uint64 depositID
        uint256 fundAmount
    ) internal virtual returns (uint64 fundingID
        Deposit storage depositEntry = _getDeposit(depositID);
        uint256 incomeIndex = moneyMarket.incomeIndex();

        (bool isNegative
        require(isNegative

        (isNegative
            depositID
            incomeIndex
        );
        require(isNegative
        if (fundAmount > surplusMagnitude) {
            fundAmount = surplusMagnitude;
        }

        // Create funding struct if one doesn't exist
        uint256 totalPrincipal =
            _depositVirtualTokenToPrincipal(
                depositID
                depositEntry.virtualTokenTotalSupply
            );
        uint256 totalPrincipalToFund;
        fundingID = depositEntry.fundingID;
        uint256 mintTokenAmount;
        if (fundingID == 0 || _getFunding(fundingID).principalPerToken == 0) {
            // The first funder
            require(block.timestamp <= type(uint64).max
            fundingList.push(
                Funding({
                    depositID: depositID
                    lastInterestPayoutTimestamp: uint64(block.timestamp)
                    recordedMoneyMarketIncomeIndex: incomeIndex
                    principalPerToken: ULTRA_PRECISION
                })
            );
            require(fundingList.length <= type(uint64).max
            fundingID = uint64(fundingList.length);
            depositEntry.fundingID = fundingID;
            totalPrincipalToFund =
                (totalPrincipal * fundAmount) /
                surplusMagnitude;
            mintTokenAmount = totalPrincipalToFund;
        } else {
            // Not the first funder
            // Trigger interest payment for existing funders
            _payInterestToFunders(fundingID

            // Compute amount of principal to fund
            uint256 principalPerToken =
                _getFunding(fundingID).principalPerToken;
            uint256 unfundedPrincipalAmount =
                totalPrincipal -
                    (fundingMultitoken.totalSupply(fundingID) *
                        principalPerToken) /
                    ULTRA_PRECISION;
            surplusMagnitude =
                (surplusMagnitude * unfundedPrincipalAmount) /
                totalPrincipal;
            if (fundAmount > surplusMagnitude) {
                fundAmount = surplusMagnitude;
            }
            totalPrincipalToFund =
                (unfundedPrincipalAmount * fundAmount) /
                surplusMagnitude;
            mintTokenAmount =
                (totalPrincipalToFund * ULTRA_PRECISION) /
                principalPerToken;
        }
        // Mint funding multitoken
        fundingMultitoken.mint(sender

        // Update relevant values
        sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex +=
            (totalPrincipalToFund * EXTRA_PRECISION) /
            incomeIndex;
        totalFundedPrincipalAmount += totalPrincipalToFund;

        // Emit event
        emit EFund(sender

        actualFundAmount = fundAmount;
    }

    function _fundTransferFunds(address sender
        internal
        virtual
    {
        // Transfer `fundAmount` stablecoins from sender
        stablecoin.safeTransferFrom(sender

        // Deposit `fundAmount` stablecoins into moneyMarket
        stablecoin.safeApprove(address(moneyMarket)
        moneyMarket.deposit(fundAmount);
    }

    /**
        @dev See {payInterestToFunders}
        @param currentMoneyMarketIncomeIndex The moneyMarket's current incomeIndex
     */
    function _payInterestToFunders(
        uint64 fundingID
        uint256 currentMoneyMarketIncomeIndex
    ) internal virtual returns (uint256 interestAmount) {
        Funding storage f = _getFunding(fundingID);
        {
            uint256 recordedMoneyMarketIncomeIndex =
                f.recordedMoneyMarketIncomeIndex;
            uint256 fundingTokenTotalSupply =
                fundingMultitoken.totalSupply(fundingID);
            uint256 recordedFundedPrincipalAmount =
                (fundingTokenTotalSupply * f.principalPerToken) /
                    ULTRA_PRECISION;

            // Update funding values
            sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex =
                sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex +
                (recordedFundedPrincipalAmount * EXTRA_PRECISION) /
                currentMoneyMarketIncomeIndex -
                (recordedFundedPrincipalAmount * EXTRA_PRECISION) /
                recordedMoneyMarketIncomeIndex;
            f.recordedMoneyMarketIncomeIndex = currentMoneyMarketIncomeIndex;

            // Compute interest to funders
            interestAmount =
                (recordedFundedPrincipalAmount *
                    currentMoneyMarketIncomeIndex) /
                recordedMoneyMarketIncomeIndex -
                recordedFundedPrincipalAmount;
        }

        // Distribute interest to funders
        if (interestAmount > 0) {
            uint256 stablecoinPrecision = 10**uint256(stablecoin.decimals());
            if (
                interestAmount >
                stablecoinPrecision / FUNDER_PAYOUT_THRESHOLD_DIVISOR
            ) {
                interestAmount = moneyMarket.withdraw(interestAmount);
                if (interestAmount > 0) {
                    stablecoin.safeApprove(
                        address(fundingMultitoken)
                        interestAmount
                    );
                    fundingMultitoken.distributeDividends(
                        fundingID
                        address(stablecoin)
                        interestAmount
                    );

                    _distributeFundingRewards(fundingID
                }
            } else {
                // interestAmount below minimum payout threshold
                emit EPayFundingInterest(fundingID
                return 0;
            }
        }

        emit EPayFundingInterest(fundingID
    }

    /**
        @dev Mints MPH rewards to the holders of an FRB. If past the deposit maturation
             only mint proportional to the time from the last distribution to the maturation.
        @param fundingID The ID of the funding
        @param rawInterestAmount The interest being distributed
     */
    function _distributeFundingRewards(
        uint64 fundingID
        uint256 rawInterestAmount
    ) internal {
        Funding storage f = _getFunding(fundingID);

        // Mint funder rewards
        uint256 maturationTimestamp =
            _getDeposit(f.depositID).maturationTimestamp;
        if (block.timestamp > maturationTimestamp) {
            // past maturation
            uint256 lastInterestPayoutTimestamp = f.lastInterestPayoutTimestamp;
            if (lastInterestPayoutTimestamp < maturationTimestamp) {
                uint256 effectiveInterestAmount =
                    (rawInterestAmount *
                        (maturationTimestamp - lastInterestPayoutTimestamp)) /
                        (block.timestamp - lastInterestPayoutTimestamp);
                mphMinter.distributeFundingRewards(
                    fundingID
                    effectiveInterestAmount
                );
            }
        } else {
            // before maturation
            mphMinter.distributeFundingRewards(fundingID
        }
        // update last payout timestamp
        require(block.timestamp <= type(uint64).max
        f.lastInterestPayoutTimestamp = uint64(block.timestamp);
    }

    /**
        @dev Used in {_withdraw}. Computes the amount of interest to distribute
             to the deposit's floating-rate bond holders. Also updates the Funding
             struct associated with the floating-rate bond.
        @param fundingID The ID of the floating-rate bond
        @param recordedFundedPrincipalAmount The amount of principal funded before the withdrawal
        @param early True if withdrawing before maturation
        @return fundingInterestAmount The amount of interest to distribute to the floating-rate bond holders
        @return refundAmount The amount of refund caused by an early withdraw
     */
    function _computeAndUpdateFundingInterestAfterWithdraw(
        uint64 fundingID
        uint256 recordedFundedPrincipalAmount
        bool early
    )
        internal
        virtual
        returns (uint256 fundingInterestAmount
    {
        Funding storage f = _getFunding(fundingID);
        uint256 currentFundedPrincipalAmount =
            (fundingMultitoken.totalSupply(fundingID) * f.principalPerToken) /
                ULTRA_PRECISION;

        // Update funding values
        {
            uint256 recordedMoneyMarketIncomeIndex =
                f.recordedMoneyMarketIncomeIndex;
            uint256 currentMoneyMarketIncomeIndex = moneyMarket.incomeIndex();
            uint256 currentFundedPrincipalAmountDivRecordedIncomeIndex =
                (currentFundedPrincipalAmount * EXTRA_PRECISION) /
                    currentMoneyMarketIncomeIndex;
            uint256 recordedFundedPrincipalAmountDivRecordedIncomeIndex =
                (recordedFundedPrincipalAmount * EXTRA_PRECISION) /
                    recordedMoneyMarketIncomeIndex;
            if (
                sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex +
                    currentFundedPrincipalAmountDivRecordedIncomeIndex >=
                recordedFundedPrincipalAmountDivRecordedIncomeIndex
            ) {
                sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex =
                    sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex +
                    currentFundedPrincipalAmountDivRecordedIncomeIndex -
                    recordedFundedPrincipalAmountDivRecordedIncomeIndex;
            } else {
                sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex = 0;
            }

            f.recordedMoneyMarketIncomeIndex = currentMoneyMarketIncomeIndex;
            totalFundedPrincipalAmount -=
                recordedFundedPrincipalAmount -
                currentFundedPrincipalAmount;

            // Compute interest to funders
            fundingInterestAmount =
                (recordedFundedPrincipalAmount *
                    currentMoneyMarketIncomeIndex) /
                recordedMoneyMarketIncomeIndex -
                recordedFundedPrincipalAmount;
        }

        // Add refund to interestAmount
        if (early) {
            Deposit storage depositEntry = _getDeposit(f.depositID);
            uint256 interestRate = depositEntry.interestRate;
            uint256 feeRate = depositEntry.feeRate;
            (
                interestOracle.updateAndQuery();
            refundAmount =
                (((recordedFundedPrincipalAmount -
                    currentFundedPrincipalAmount) * PRECISION)
                    .decmul(moneyMarketInterestRatePerSecond) *
                    (depositEntry.maturationTimestamp - block.timestamp)) /
                PRECISION;
            uint256 maxRefundAmount =
                (recordedFundedPrincipalAmount - currentFundedPrincipalAmount)
                    .decdiv(PRECISION + interestRate + feeRate)
                    .decmul(interestRate + feeRate);
            refundAmount = refundAmount <= maxRefundAmount
                ? refundAmount
                : maxRefundAmount;
            fundingInterestAmount += refundAmount;
        }

        emit EPayFundingInterest(
            fundingID
            fundingInterestAmount
            refundAmount
        );
    }

    /**
        Internal getter functions
     */

    /**
        @dev See {getDeposit}
     */
    function _getDeposit(uint64 depositID)
        internal
        view
        returns (Deposit storage)
    {
        return deposits[depositID - 1];
    }

    /**
        @dev See {getFunding}
     */
    function _getFunding(uint64 fundingID)
        internal
        view
        returns (Funding storage)
    {
        return fundingList[fundingID - 1];
    }

    /**
        @dev Converts a virtual token value into the corresponding principal value.
             Principal refers to deposit + full interest + fee.
        @param depositID The ID of the deposit of the virtual tokens
        @param virtualTokenAmount The virtual token value
        @return The corresponding principal value
     */
    function _depositVirtualTokenToPrincipal(
        uint64 depositID
        uint256 virtualTokenAmount
    ) internal view virtual returns (uint256) {
        Deposit storage depositEntry = _getDeposit(depositID);
        uint256 depositInterestRate = depositEntry.interestRate;
        return
            virtualTokenAmount.decdiv(depositInterestRate + PRECISION).decmul(
                depositInterestRate + depositEntry.feeRate + PRECISION
            );
    }

    /**
        @dev See {Rescuable._authorizeRescue}
     */
    function _authorizeRescue(
        address
        address /*target*/
    ) internal view override {
        require(msg.sender == owner()
    }

    /**
        @dev See {surplus}
        @param incomeIndex The moneyMarket's current incomeIndex
     */
    function _surplus(uint256 incomeIndex)
        internal
        virtual
        returns (bool isNegative
    {
        // compute totalInterestOwedToFunders
        uint256 currentValue =
            (incomeIndex *
                sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex) /
                EXTRA_PRECISION;
        uint256 initialValue = totalFundedPrincipalAmount;
        uint256 totalInterestOwedToFunders;
        if (currentValue > initialValue) {
            totalInterestOwedToFunders = currentValue - initialValue;
        }

        // compute surplus
        uint256 totalValue = moneyMarket.totalValue(incomeIndex);
        uint256 totalOwed =
            totalDeposit +
                totalInterestOwed +
                totalFeeOwed +
                totalInterestOwedToFunders;
        if (totalValue >= totalOwed) {
            // Locked value more than owed deposits
            isNegative = false;
            surplusAmount = totalValue - totalOwed;
        } else {
            // Locked value less than owed deposits
            isNegative = true;
            surplusAmount = totalOwed - totalValue;
        }
    }

    /**
        @dev See {rawSurplusOfDeposit}
        @param currentMoneyMarketIncomeIndex The moneyMarket's current incomeIndex
     */
    function _rawSurplusOfDeposit(
        uint64 depositID
        uint256 currentMoneyMarketIncomeIndex
    ) internal virtual returns (bool isNegative
        Deposit storage depositEntry = _getDeposit(depositID);
        uint256 depositTokenTotalSupply = depositEntry.virtualTokenTotalSupply;
        uint256 depositAmount =
            depositTokenTotalSupply.decdiv(
                depositEntry.interestRate + PRECISION
            );
        uint256 interestAmount = depositTokenTotalSupply - depositAmount;
        uint256 feeAmount = depositAmount.decmul(depositEntry.feeRate);
        uint256 currentDepositValue =
            (depositAmount * currentMoneyMarketIncomeIndex) /
                depositEntry.averageRecordedIncomeIndex;
        uint256 owed = depositAmount + interestAmount + feeAmount;
        if (currentDepositValue >= owed) {
            // Locked value more than owed deposits
            isNegative = false;
            surplusAmount = currentDepositValue - owed;
        } else {
            // Locked value less than owed deposits
            isNegative = true;
            surplusAmount = owed - currentDepositValue;
        }
    }

    /**
        Param setters (only callable by the owner)
     */
    function setFeeModel(address newValue) external onlyOwner {
        require(newValue.isContract()
        feeModel = IFeeModel(newValue);
        emit ESetParamAddress(msg.sender
    }

    function setInterestModel(address newValue) external onlyOwner {
        require(newValue.isContract()
        interestModel = IInterestModel(newValue);
        emit ESetParamAddress(msg.sender
    }

    function setInterestOracle(address newValue) external onlyOwner {
        require(newValue.isContract()
        interestOracle = IInterestOracle(newValue);
        require(interestOracle.moneyMarket() == moneyMarket
        emit ESetParamAddress(msg.sender
    }

    function setRewards(address newValue) external onlyOwner {
        require(newValue.isContract()
        moneyMarket.setRewards(newValue);
        emit ESetParamAddress(msg.sender
    }

    function setMPHMinter(address newValue) external onlyOwner {
        require(newValue.isContract()
        mphMinter = MPHMinter(newValue);
        emit ESetParamAddress(msg.sender
    }

    function setMaxDepositPeriod(uint64 newValue) external onlyOwner {
        require(newValue > 0
        MaxDepositPeriod = newValue;
        emit ESetParamUint(msg.sender
    }

    function setMinDepositAmount(uint256 newValue) external onlyOwner {
        require(newValue > 0
        MinDepositAmount = newValue;
        emit ESetParamUint(msg.sender
    }

    function setGlobalDepositCap(uint256 newValue) external onlyOwner {
        GlobalDepositCap = newValue;
        emit ESetParamUint(msg.sender
    }

    function setDepositNFTBaseURI(string calldata newURI) external onlyOwner {
        depositNFT.setBaseURI(newURI);
    }

    function setDepositNFTContractURI(string calldata newURI)
        external
        onlyOwner
    {
        depositNFT.setContractURI(newURI);
    }

    function skimSurplus(address recipient) external onlyOwner {
        (bool isNegative
        if (!isNegative) {
            surplusMagnitude = moneyMarket.withdraw(surplusMagnitude);
            stablecoin.safeTransfer(recipient
        }
    }

    function decreaseFeeForDeposit(uint64 depositID
        external
        onlyOwner
    {
        Deposit storage depositStorage = _getDeposit(depositID);
        uint256 feeRate = depositStorage.feeRate;
        uint256 interestRate = depositStorage.interestRate;
        uint256 virtualTokenTotalSupply =
            depositStorage.virtualTokenTotalSupply;
        require(newFeeRate < feeRate
        uint256 depositAmount =
            virtualTokenTotalSupply.decdiv(interestRate + PRECISION);

        // update fee rate
        depositStorage.feeRate = newFeeRate;

        // update interest rate
        // fee reduction is allocated to interest
        uint256 reducedFeeAmount = depositAmount.decmul(feeRate - newFeeRate);
        depositStorage.interestRate =
            interestRate +
            reducedFeeAmount.decdiv(depositAmount);

        // update global amounts
        totalInterestOwed += reducedFeeAmount;
        totalFeeOwed -= reducedFeeAmount;
    }

    uint256[32] private __gap;
}
