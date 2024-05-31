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
