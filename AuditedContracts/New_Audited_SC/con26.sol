// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.3;

import {DecMath} from ""./libs/DecMath.sol"";
import {DInterest} from ""./DInterest.sol"";

contract DInterestLens {
    using DecMath for uint256;

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
        @notice Computes the amount of stablecoins that can be withdrawn
                by burning `virtualTokenAmount` virtual tokens from the deposit
                with ID `depositID` at time `timestamp`.
        @dev The queried timestamp should >= the deposit's lastTopupTimestamp
             the information before this time is forgotten.
        @param pool The DInterest pool
        @param depositID The ID of the deposit
        @param virtualTokenAmount The amount of virtual tokens to burn
        @return withdrawableAmount The amount of stablecoins (after fee) that can be withdrawn
        @return feeAmount The amount of fees that will be given to the beneficiary
     */
    function withdrawableAmountOfDeposit(
        DInterest pool
        uint64 depositID
        uint256 virtualTokenAmount
    ) external view returns (uint256 withdrawableAmount
        // Verify input
        DInterest.Deposit memory depositEntry = pool.getDeposit(depositID);
        if (virtualTokenAmount == 0) {
            return (0
        } else {
            if (virtualTokenAmount > depositEntry.virtualTokenTotalSupply) {
                virtualTokenAmount = depositEntry.virtualTokenTotalSupply;
            }
        }

        // Compute token amounts
        bool early = block.timestamp < depositEntry.maturationTimestamp;
        uint256 depositAmount =
            virtualTokenAmount.decdiv(depositEntry.interestRate + PRECISION);
        uint256 interestAmount = early ? 0 : virtualTokenAmount - depositAmount;
        withdrawableAmount = depositAmount + interestAmount;

        if (early) {
            // apply fee to withdrawAmount
            uint256 earlyWithdrawFee =
                pool.feeModel().getEarlyWithdrawFeeAmount(
                    address(pool)
                    depositID
                    withdrawableAmount
                );
            feeAmount = earlyWithdrawFee;
            withdrawableAmount -= earlyWithdrawFee;
        } else {
            feeAmount = depositAmount.decmul(depositEntry.feeRate);
        }
    }

    /**
        @notice Computes the floating-rate interest accrued in the floating-rate
                bond with ID `fundingID`.
        @param pool The DInterest pool
        @param fundingID The ID of the floating-rate bond
        @return fundingInterestAmount The interest accrued
     */
    function accruedInterestOfFunding(DInterest pool
        external
        returns (uint256 fundingInterestAmount)
    {
        DInterest.Funding memory f = pool.getFunding(fundingID);
        uint256 fundingTokenTotalSupply =
            pool.fundingMultitoken().totalSupply(fundingID);
        uint256 recordedFundedPrincipalAmount =
            (fundingTokenTotalSupply * f.principalPerToken) / ULTRA_PRECISION;
        uint256 recordedMoneyMarketIncomeIndex =
            f.recordedMoneyMarketIncomeIndex;
        uint256 currentMoneyMarketIncomeIndex =
            pool.moneyMarket().incomeIndex();
        require(currentMoneyMarketIncomeIndex > 0

        // Compute interest to funders
        fundingInterestAmount =
            (recordedFundedPrincipalAmount * currentMoneyMarketIncomeIndex) /
            recordedMoneyMarketIncomeIndex -
            recordedFundedPrincipalAmount;
    }

    /**
        @notice A floating-rate bond is no longer active if its principalPerToken becomes 0
                which occurs when the corresponding deposit is completely withdrawn. When
                such a deposit is topped up
                be created.
        @param pool The DInterest pool
        @param fundingID The ID of the floating-rate bond
        @return True if the funding is active
     */
    function fundingIsActive(DInterest pool
        external
        view
        returns (bool)
    {
        return pool.getFunding(fundingID).principalPerToken > 0;
    }

    /**
        @notice Computes the floating interest amount owed to deficit funders
                when a funded deposit is withdrawn.
                Formula: \sum_i recordedFundedPrincipalAmount_i * (incomeIndex / recordedMoneyMarketIncomeIndex_i - 1)
                = incomeIndex * (\sum_i recordedFundedPrincipalAmount_i / recordedMoneyMarketIncomeIndex_i)
                - \sum_i recordedFundedPrincipalAmount_i
                where i refers to a funding
        @param pool The DInterest pool
        @return interestOwed The floating-rate interest accrued to all floating-rate bond holders
     */
    function totalInterestOwedToFunders(DInterest pool)
        public
        virtual
        returns (uint256 interestOwed)
    {
        uint256 currentValue =
            (pool.moneyMarket().incomeIndex() *
                pool
                    .sumOfRecordedFundedPrincipalAmountDivRecordedIncomeIndex()) /
                EXTRA_PRECISION;
        uint256 initialValue = pool.totalFundedPrincipalAmount();
        if (currentValue < initialValue) {
            return 0;
        }
        return currentValue - initialValue;
    }

    /**
        @notice Computes the surplus of a deposit
                unfunded part of the deposit. If the deposit is not funded
                return the same value as {rawSurplusOfDeposit}.
        @param depositID The ID of the deposit
        @return isNegative True if the surplus is negative
        @return surplusAmount The absolute value of the surplus
     */
    function surplusOfDeposit(DInterest pool
        public
        virtual
        returns (bool isNegative
    {
        (isNegative

        DInterest.Deposit memory depositEntry = pool.getDeposit(depositID);
        if (depositEntry.fundingID != 0) {
            uint256 totalPrincipal =
                _depositVirtualTokenToPrincipal(
                    depositEntry
                    depositEntry.virtualTokenTotalSupply
                );
            uint256 principalPerToken =
                pool.getFunding(depositEntry.fundingID).principalPerToken;
            uint256 unfundedPrincipalAmount =
                totalPrincipal -
                    (pool.fundingMultitoken().totalSupply(
                        depositEntry.fundingID
                    ) * principalPerToken) /
                    ULTRA_PRECISION;
            surplusAmount =
                (surplusAmount * unfundedPrincipalAmount) /
                totalPrincipal;
        }
    }

    /**
        @dev Converts a virtual token value into the corresponding principal value.
             Principal refers to deposit + full interest + fee.
        @param depositEntry The deposit struct
        @param virtualTokenAmount The virtual token value
        @return The corresponding principal value
     */
    function _depositVirtualTokenToPrincipal(
        DInterest.Deposit memory depositEntry
        uint256 virtualTokenAmount
    ) internal pure virtual returns (uint256) {
        uint256 depositInterestRate = depositEntry.interestRate;
        return
            virtualTokenAmount.decdiv(depositInterestRate + PRECISION).decmul(
                depositInterestRate + depositEntry.feeRate + PRECISION
            );
    }
}
