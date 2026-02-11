# [Brix Money Report](https://code4rena.com/reports/2025-11-brix-money)

| ID | Title |
|:--:|:---|
| [L-1](#l-1-updating-vestingperiod-makes-fully-vested-rewards-become-unvested-again) | Updating `vestingPeriod` makes fully-vested rewards become unvested again |
| [L-2](#l-2-setting-cooldownduration-to-zero-unintentionally-disables-all-cross-chain-redemption) | Setting `cooldownDuration` to zero unintentionally disables all cross-chain redemption |

# [L-1] Updating `vestingPeriod` makes fully-vested rewards become unvested again
https://github.com/code-423n4/2025-11-brix-money/blob/79e36aeda1b0091fa3ecd96f398517b31603f5d2/src/token/wiTRY/StakediTry.sol#L95

## Finding description
The `setVestingPeriod()` function allows the admin to update the vesting duration. Although it checks `getUnvestedAmount()` > 0 and blocks changes during an active vesting cycle, it does not reset `vestingAmount` after the cycle has ended.
If the admin updates the `vestingPeriod` after rewards have fully vested, the `getUnvestedAmount()` will recompute vesting using the new `vestingPeriod`+ stale `vestingAmount`, making already-vested rewards unvest again and reduces `totalAssets`.

```solidity
function getUnvestedAmount() public view returns (uint256) {
    // ...
    unchecked {
        deltaT = (vestingPeriod - timeSinceLastDistribution);
    }
    return (deltaT * vestingAmount) / vestingPeriod; // Stale vestingAmount is used here
```
Example:
- Initial State: `vestingAmount` = 3600, `vestingPeriod` = 3600s.
- T = 3601s (Cycle finished): `getUnvestedAmount()` returns 0. `totalAssets` includes full 3600 tokens.
- Admin calls `setVestingPeriod(7200)` to extend the period to 2 hours.
- `getUnvestedAmount()` calculates unvested amount using the old amount (3600) and new period (7200):
    $$ \text{Unvested} = \frac{(7200 - 3601) \times 3600}{7200} \approx 1799.5 $$
- `totalAssets` instantly drops by ~1800 tokens.

## Impact
This bug causes severe economic issues for the vault:
- Share Price Flash Crash: The ERC4626 share price is derived from `totalAssets()`. When stale vested rewards suddenly become unvested again, the asset value drops immediately.
- Direct User Loss：All vault share holders lose value. Users redeeming after the update receive fewer assets because the contract effectively removes part of their already-earned rewards.
- Arbitrage Opportunity: An attacker can withdraw at the high price before the admin update, then deposit back at the artificially low price, extracting value from passive stakers.

## Recommended mitigation steps
Reset `vestingAmount` to 0 in `setVestingPeriod()` if the previous cycle has finished. Since the logic already ensures `getUnvestedAmount() == 0`, clearing the historical state is safe and necessary.
```diff
function setVestingPeriod(uint256 _vestingPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
    // ...
    if (getUnvestedAmount() > 0) {
        revert StillVesting();
    }
    
+   if (vestingAmount > 0) vestingAmount = 0; // FIX: Clear the historical amount
    // ...
```

## POC
Copy the test contract below into the `test/` folder and run `forge test --mt test_VestedRewardsBecomeUnvested -vv`
```solidity
import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/token/wiTRY/StakediTry.sol"; 
import {MockERC20} from "./mocks/MockERC20.sol";

contract PoC is Test {
    StakediTry public vault;
    MockERC20 public iTryToken;

    address public admin = makeAddr("admin");
    address public rewarder = makeAddr("rewarder");
    address public user = makeAddr("user");
    uint256 constant INITIAL_VESTING_PERIOD = 3600; // 1 hour

    function setUp() public {
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry
        vm.prank(admin);
        vault = new StakediTry(IERC20(address(iTryToken)), rewarder, admin);

        iTryToken.mint(rewarder, 3600 ether); 
        iTryToken.mint(user, 1000 ether); 

        vm.startPrank(user);
        iTryToken.approve(address(vault), type(uint256).max);
        vault.deposit(1000 ether, user);
        vm.stopPrank();
    }

    function test_VestedRewardsBecomeUnvested() public {
        // --- Step 1: Inject rewards ---
        uint256 rewardAmount = 3600 ether;
        
        vm.startPrank(rewarder);
        iTryToken.approve(address(vault), rewardAmount);
        vault.transferInRewards(rewardAmount);
        vm.stopPrank();

        console.log("1.Rewards injected:", rewardAmount);
        console.log("  Initial Vesting Period:", vault.getVestingPeriod());

        // --- Step 2: Warp forward to fully vest rewards (3601 seconds) ---
        vm.warp(block.timestamp + INITIAL_VESTING_PERIOD + 1);

        uint256 unvestedBefore = vault.getUnvestedAmount();
        uint256 vestingAmountBefore = vault.vestingAmount(); 
        uint256 totalAssetsBefore = vault.totalAssets();

        console.log("2.Time warped past vesting period.");
        console.log("  Unvested Amount (Should be 0):", unvestedBefore);
        console.log("  Total Assets (Fully Vested): ", totalAssetsBefore);

        assertEq(unvestedBefore, 0, "Rewards should be fully vested.");
        assertEq(totalAssetsBefore, 1000 ether + 3600 ether, "Total assets check");

        // --- Step 3: Admin updates vesting period (triggering the bug) ---
        uint256 newVestingPeriod = 7200; 

        console.log("3.Extends vesting period to:", newVestingPeriod);
        
        vm.prank(admin);
        vault.setVestingPeriod(newVestingPeriod); // Allowed because getUnvestedAmount() == 0

        // --- Step 4: Verify ---
        uint256 unvestedAfter = vault.getUnvestedAmount();
        uint256 totalAssetsAfter = vault.totalAssets();
        uint256 vestingAmountAfter = vault.vestingAmount();

        console.log("  Unvested Amount (Zombie):    ", unvestedAfter);
        console.log("  Total Assets (After Update): ", totalAssetsAfter);
        console.log("  Missing Assets:              ", totalAssetsBefore - totalAssetsAfter);
        assertEq(vestingAmountBefore, vestingAmountAfter); // vestingAmount should not have changed
        assertGt(unvestedAfter, 0, "Expired rewards resurrected as unvested");
        assertLt(totalAssetsAfter, totalAssetsBefore, "Total Assets dropped unexpectedly");
    }
}
```

# [L-2] Setting `cooldownDuration` to zero unintentionally disables all cross-chain redemption
https://github.com/code-423n4/2025-11-brix-money/blob/79e36aeda1b0091fa3ecd96f398517b31603f5d2/src/token/wiTRY/StakediTryCooldown.sol#L120-L131
https://github.com/code-423n4/2025-11-brix-money/blob/79e36aeda1b0091fa3ecd96f398517b31603f5d2/src/token/wiTRY/crosschain/wiTryVaultComposer.sol#L61-L84

## Finding description
The `StakediTryV2` vault allows the admin to set `cooldownDuration(0)`. According to the design and documentation, this switches the vault into standard ERC4626 mode, enabling instant withdrawals through redeem/withdraw and disabling all cooldown-related logic.
However, the cross-chain adapter `wiTryVaultComposer` is hardcoded to only use cooldown-based functions (`unstakeThroughComposer()` and `fastRedeemThroughComposer()`) and contains no logic for the “no-cooldown” mode
```solidity
function handleCompose(address _oftIn, bytes32 _composeFrom, bytes memory _composeMsg, uint256 _amount) external payable override {
        //...
        if (_oftIn == ASSET_OFT) {
            _depositAndSend(_composeFrom, _amount, sendParam, address(this));
        } else if (_oftIn == SHARE_OFT) {
            if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
                _initiateCooldown(_composeFrom, _amount);
            } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
                _fastRedeem(_composeFrom, _amount, sendParam, address(this));
            } else {
                revert InitiateCooldownRequired();
        //..
```
- When the admin sets `cooldownDuration = 0`, the vault enters ERC4626 mode.
- The `ensureCooldownOn` modifier in `StakediTryCrosschain` blocks `cooldownSharesByComposer()` and all fast-redeem functions.
- Although `unstakeThroughComposer()` has no modifier, it cannot complete because it depends on writing `UserCooldown` data, which is no longer allowed when cooldown is off.
- When cross-chain users trigger an unstake through `UnstakeMessenger`, the composer still calls the cooldown-based interfaces, causing every transaction to revert.

## Impact

- The `UnstakeMessenger` flow becomes unusable for all cross-chain users. Even valid redemption requests fail on the hub chain.
- The system behaves opposite to the admin’s intention. The admin expects to improve UX by removing the waiting period, but instead disables all cross-chain redemption paths.
- User funds are not lost, but users must manually bridge wiTryOFT back to the hub chain and interact with the vault directly

## Recommended mitigation steps
In `_handleUnstake()` and `handleCompose()`, check the vault’s cooldown duration before selecting the redemption path. If `cooldownDuration == 0`, the composer should call the standard ERC4626 `redeem()` function instead of cooldown-based functions.
```solidity
function _handleUnstake(...) internal override {
    uint256 assets;
    if (IStakediTry(address(VAULT)).cooldownDuration() == 0) {
        // Use standard redeem if cooldown is off
        assets = VAULT.redeem(amount, address(this), address(this));
    } else {
        // Use existing logic if cooldown is on
        assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
    }
    // ... continue with sending assets back
```

## POC
The PoC shows that once the admin disables the cooldown, all cross-chain redemption paths fail for all users.
Copy the test contract below into the `test/` folder and run `forge test --mt test_AllCrossChainMethodsFailWhenCooldownZero`
```solidity
import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {StakediTryCrosschain} from "../src/token/wiTRY/StakediTryCrosschain.sol";
import {IStakediTryCrosschain} from "../src/token/wiTRY/interfaces/IStakediTryCrosschain.sol";
import {IStakediTry} from "../src/token/wiTRY/interfaces/IStakediTry.sol";
import {IStakediTryCooldown} from "../src/token/wiTRY/interfaces/IStakediTryCooldown.sol";
import {IStakediTryFastRedeem} from "../src/token/wiTRY/interfaces/IStakediTryFastRedeem.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract PoC is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    StakediTryCrosschain public vault;

    address public owner;
    address public rewarder;
    address public treasury;
    address public composer; 
    address public crosschainReceiver;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public COMPOSER_ROLE;

    function setUp() public {
        owner = makeAddr("owner");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        composer = makeAddr("Composer");
        crosschainReceiver = makeAddr("CrosschainReceiver");

        // Deploy iTry
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner, 
            owner 
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));

        // Deploy Vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(IERC20(address(itryToken)), rewarder, owner, treasury);

        // Setup Roles & Config
        COMPOSER_ROLE = vault.COMPOSER_ROLE();

        vm.startPrank(owner);
        vault.grantRole(COMPOSER_ROLE, composer);
        vault.setFastRedeemEnabled(true);
        vault.setFastRedeemFee(1000);
        vm.stopPrank();
        _mintAndDeposit(composer, 1000e18);
    }

    function _mintAndDeposit(address user, uint256 amount) internal {
        vm.prank(owner);
        itryToken.mint(user, amount);

        vm.startPrank(user);
        itryToken.approve(address(vault), amount);
        vault.deposit(amount, user);
        vm.stopPrank();
    }

    function test_AllCrossChainMethodsFailWhenCooldownZero() public {
        // By default, cooldownDuration > 0 and all cross-chain functionalities work normally
        uint256 defaultDuration = vault.cooldownDuration();
        assertGt(defaultDuration, 0, "Setup check: Cooldown should be active");

        // Admin disables cooldown.
        // According to the official documentation, setting cooldown to zero should re-enable standard ERC4626 redeem/withdraw for instant withdrawals.
        vm.prank(owner);
        vault.setCooldownDuration(0);

        // --- 1: Standard cross-chain redemption (Initiate Cooldown) is blocked ---
        vm.prank(composer);
        vm.expectRevert(IStakediTry.OperationNotAllowed.selector); // Expected revert: OperationNotAllowed (due to ensureCooldownOn modifier)
        vault.cooldownSharesByComposer(10e18, crosschainReceiver);

        // --- 2: Fast cross-chain redeem is blocked ---
        // Composer attempts to perform a fast redeem
        vm.prank(composer);
        vm.expectRevert(IStakediTry.OperationNotAllowed.selector); // Expected revert: OperationNotAllowed (due to ensureCooldownOn modifier)
        vault.fastRedeemThroughComposer(10e18, crosschainReceiver, composer);

        // --- 3: Fast cross-chain withdraw is blocked ---
        vm.prank(composer);
        vm.expectRevert(IStakediTry.OperationNotAllowed.selector);
        vault.fastWithdrawThroughComposer(10e18, crosschainReceiver, composer);
    }
}
```
