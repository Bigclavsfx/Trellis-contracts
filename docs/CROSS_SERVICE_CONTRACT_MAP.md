# Cross-Service Contract Map: Domain Events & Integration Boundaries

> **Resolves:** [#235](https://github.com/TRELLIS-STELLAR/Trellis-contracts/issues/235)  
> **Scope:** All contracts in the `contracts/` workspace — `aid-contract`, `oracle-contract`,
> `payments-contract`, `governance-contract`, `nft-marketplace`, `access-control`,
> `treasury-contract`, `referral-contract`, `registry-contract`, `upgradeability`,
> `rebalancer-contract` — plus the `shared` library.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Shared Foundation (`shared` crate)](#2-shared-foundation-shared-crate)
3. [Contract Inventory](#3-contract-inventory)
4. [Domain Event Catalogue](#4-domain-event-catalogue)
5. [Cross-Contract Call Map](#5-cross-contract-call-map)
6. [Integration Boundary Specifications](#6-integration-boundary-specifications)
7. [Version & Schema Rules](#7-version--schema-rules)
8. [Failure Modes & Allowed Failure Behavior](#8-failure-modes--allowed-failure-behavior)
9. [Operational Edge Cases](#9-operational-edge-cases)
10. [Rollback & Recovery Procedures](#10-rollback--recovery-procedures)
11. [Public API Compatibility Guarantees](#11-public-api-compatibility-guarantees)

---

## 1. Architecture Overview

All contracts are Soroban smart contracts compiled to WASM and deployed on Stellar. They share a
single internal library (`shared`) but have **zero compile-time Rust dependencies on each other**.
Cross-contract communication happens exclusively at runtime via Soroban's contract invocation
mechanism (address + function name).

```
┌─────────────────────────────────────────────────────────────────────┐
│                        shared  (library crate)                       │
│  errors · auth (Role/Permission) · events (emitters) · payments      │
│  storage helpers · compat (schema migration) · migration journal     │
└──────────────┬──────────────────────────────────────────────────────┘
               │  every contract depends on shared; no contract depends
               │  on another contract at compile time
               ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │                     Runtime call graph                               │
 │                                                                      │
 │  governance ──SetTargetParameter──▶ any target contract              │
 │                                                                      │
 │  oracle ──slash penalty──▶ treasury                                  │
 │                                                                      │
 │  treasury ──accrue──▶ referral                                       │
 │  treasury ──strategy calls──▶ reserve strategy contracts             │
 │                                                                      │
 │  referral ──distribute_reward──▶ treasury                            │
 │  referral ──get_contract──▶ registry  (fallback)                     │
 │                                                                      │
 │  nft-marketplace ──price query──▶ oracle  (optional)                 │
 │                                                                      │
 │  upgradeability ──migration hooks──▶ hook contracts                  │
 │                                                                      │
 │  aid / oracle / treasury / payments / nft-marketplace                │
 │          ──transfer / transfer_from──▶ Soroban token (SAC/SEP-41)   │
 └─────────────────────────────────────────────────────────────────────┘
```

**Dependency direction rule:** The call graph is intentionally acyclic between Trellis contracts
except for the `treasury ↔ referral` pair, which is permitted because `treasury.distribute_reward`
calls `referral.accrue` _after_ the reward funds have been credited — there is no re-entrancy path
back into treasury during that call.

---

## 2. Shared Foundation (`shared` crate)

### 2.1 Canonical Error Codes

Every contract uses `shared::errors::Error` (plus its own narrower error type for contract-specific
codes). The numeric ranges are reserved by domain:

| Range    | Domain                    |
|----------|---------------------------|
| 1 – 41   | General / cross-cutting   |
| 12 – 28  | Governance                |
| 16 – 24  | Registry / schema         |
| 700 – 711| Payments / escrow         |
| 900 – 910| Upgradeability            |
| 950 – 954| State-transition guards   |
| 1000 – 1008 | NFT Marketplace        |

Contract-local error types occupy separate ranges:
| Contract        | Error type        | Range     |
|-----------------|-------------------|-----------|
| `aid-contract`  | `AidError`        | 100 – 117 |
| `oracle-contract` | `OracleError`   | 500 – 520 |

**Rule:** New contract-specific error codes must use the range documented for that contract.
General cross-cutting errors must be added to `shared::errors::Error` and discussed in a PR.

### 2.2 Role & Permission Model

```rust
// shared::auth
pub enum Role {
    Admin, Upgrader, TreasuryManager, Pauser,
    ReferralManager, OracleSigner, EndUser, ServiceActor, Support,
}

pub enum Permission {
    UseOwnResources, ManageConfiguration, ManageRoles,
    TreasuryOperations, PauseContracts, ReferralConfiguration,
    SubmitOracle, UpgradeContracts, ReadAuditTrail,
    ServiceOperation, ImpersonateUser,
}
```

`shared::auth::role_for_permission()` is the canonical mapping between the two. Every contract
enforces roles using `shared::auth::require_admin`, `require_role`, or the
`access-control` contract's `has_action_permission` matrix — never custom bespoke guards.

### 2.3 Correlation IDs

All canonical event emitters in `shared::events` accept a `correlation_id: BytesN<32>` so that
events emitted across multiple contracts in a single logical workflow can be grouped by an
off-chain indexer.

**Policy:**
- Length: 8 – 64 significant bytes (trailing zero-bytes ignored).
- Alphabet: `[0-9A-Za-z._:-]`.
- Validated by `shared::events::validate_correlation_id`.
- Contracts that have no meaningful workflow correlation use
  `aid_contract::correlation::zero_correlation_id()` as a sentinel.

### 2.4 Shared Payments Primitives

`shared::payments` provides the reusable escrow engine used by `payments-contract`:

```rust
pub struct EscrowRecord {
    id: u64, depositor: Address, beneficiary: Address,
    token: Address, amount: i128, expiry_ledger: u32, state: EscrowState,
}
pub enum EscrowState { Active, Released, Refunded }
pub struct FeeConfig { rate_bps: i128, recipient: Address }
```

`create_escrow`, `release_escrow`, `refund_escrow`, `release_milestone`, `resolve_dispute`,
`safe_transfer`, `safe_transfer_from_contract`, `calculate_fee`, `deduct_fee`.

### 2.5 Schema Compatibility Module

`shared::compat` provides versioned aid-record migration:

```rust
pub const RECORD_SCHEMA_V1: u32 = 1;
pub const RECORD_SCHEMA_V2: u32 = 2;  // current

pub struct LegacyAidRecord { ... }  // V1 layout
pub struct CurrentAidRecord { ... } // V2 layout
pub enum VersionedAidRecord { V1(LegacyAidRecord), V2(CurrentAidRecord) }

pub fn migrate_v1_to_v2(record: LegacyAidRecord) -> CurrentAidRecord;
pub fn downgrade_v2_to_v1(record: CurrentAidRecord) -> LegacyAidRecord;
pub fn ensure_supported_version(v: u32) -> Result<(), Error>;
```

---

## 3. Contract Inventory

| Contract           | Purpose                                   | Local error type | Error range |
|--------------------|-------------------------------------------|------------------|-------------|
| `aid-contract`     | Humanitarian aid escrow & disbursement    | `AidError`       | 100 – 117   |
| `oracle-contract`  | Decentralized price oracle with staking   | `OracleError`    | 500 – 520   |
| `payments-contract`| Payment gateway, escrow, batch payouts    | `shared::Error`  | 700 – 711   |
| `governance-contract` | Multi-sig on-chain governance          | `shared::Error`  | 12 – 28     |
| `nft-marketplace`  | NFT listings, auctions, offers, royalties | `MarketError`    | 1000 – 1008 |
| `access-control`   | RBAC with hierarchical roles & invitations| `AccessControlError` | custom  |
| `treasury-contract`| Multi-asset treasury with strategies      | `shared::Error`  | 1 – 41      |
| `referral-contract`| Multi-tier referral rewards               | `shared::Error`  | 1 – 41      |
| `registry-contract`| Name-to-address registry                  | `shared::Error`  | 16 – 24     |
| `upgradeability`   | Timelock-gated WASM upgrade registry      | `UpgradeError`   | 900 – 910   |
| `rebalancer-contract` | Multi-asset rebalancing executor       | `RebalancerError`| 1 – 4       |

---

## 4. Domain Event Catalogue

Every event is emitted via a `shared::events` emitter. Topics follow a two-symbol convention
`(domain, action)` with an optional third `correlation_id` slot. The tables below document the
**canonical topic**, **data payload**, **producing contract(s)**, and the **consuming
contracts / off-chain services** that are expected to observe each event.

### 4.1 Aid Events

| Event constant        | Topics                              | Payload                                                           | Producer        | Consumers                              |
|-----------------------|-------------------------------------|-------------------------------------------------------------------|-----------------|----------------------------------------|
| `AID_CREATED`         | `("aid", "created", corr_id)`       | `(aid_id: u64, donor: Address, recipient: Address, amount: i128, created_at: u64, expires_at: u64)` | `aid-contract` | Off-chain indexer, referral accrual trigger |
| `AID_CLAIMED`         | `("aid", "claimed", corr_id)`       | `(aid_id: u64, recipient: Address, amount: i128, settled_at: u64)` | `aid-contract` | Off-chain indexer                      |
| `AID_SETTLED`         | `("aid", "settled", corr_id)`       | `(aid_id: u64, amount: i128)`                                     | `aid-contract`  | Off-chain indexer                      |
| `AID_REFUNDED`        | `("aid", "refunded", corr_id)`      | `(aid_id: u64, donor: Address, amount: i128, refunded_at: u64)`   | `aid-contract`  | Off-chain indexer                      |
| `IMPORT_SIMULATED`    | `("imp_sim",)`                      | `(item_count: u32, report: ImportReport)`                         | `aid-contract`  | Admin tooling                          |
| `IMPORT_COMMITTED`    | `("imp_cmt",)`                      | `(item_count: u32, report: ImportReport)`                         | `aid-contract`  | Admin tooling, off-chain indexer        |
| `IMPORT_FAILED`       | `("imp_fail",)`                     | `(item_count: u32, report: ImportReport)`                         | `aid-contract`  | Alerting                               |

**Required fields — `AID_CREATED`:** `aid_id`, `donor`, `recipient`, `amount` are mandatory. Omitting
any of these is a breaking change.

**Version rule:** Adding a new optional field to the payload requires incrementing
`RECORD_SCHEMA_V2` → `V3` in `shared::compat` and providing `migrate_v2_to_v3`.

### 4.2 Oracle Events

| Event constant             | Topics                        | Payload                                                                          | Producer         | Consumers                                    |
|----------------------------|-------------------------------|----------------------------------------------------------------------------------|------------------|----------------------------------------------|
| `("oracle", "sub_reg")`    | submitter registered          | `(submitter: Address, timestamp: u64, correlation_id: Symbol)`                   | `oracle-contract`| Admin tooling                                |
| `("oracle", "sub_del")`    | submitter deactivated         | `(submitter: Address, timestamp: u64, correlation_id: Symbol)`                   | `oracle-contract`| Admin tooling, slashing monitors             |
| `("oracle", "price")`      | price submitted               | `(feed_id: Symbol, price: i128, submitter: Address, timestamp: u64, corr_id: Symbol)` | `oracle-contract` | `nft-marketplace` (optional), off-chain analytics |
| `("oracle", "stale")`      | staleness window changed      | `(window_seconds: u64, timestamp: u64, correlation_id: Symbol)`                  | `oracle-contract`| Admin tooling                                |
| `("oracle", "staked")`     | submitter staked              | `(submitter: Address, amount: i128, total_stake: i128, timestamp: u64)`          | `oracle-contract`| Staking dashboards                           |
| `("oracle", "slashed")`    | submitter slashed             | `(submitter: Address, penalty_amount: i128, remaining_stake: i128, reason: Symbol, timestamp: u64)` | `oracle-contract` | `treasury-contract` (receives slash funds), alerting |
| `("oracle", "unbond")`     | unbonding initiated           | `(submitter: Address, amount: i128, unlock_time: u64, timestamp: u64)`           | `oracle-contract`| Staking dashboards                           |
| `("oracle", "withdrawn")`  | stake withdrawn               | `(submitter: Address, amount: i128, timestamp: u64)`                             | `oracle-contract`| Staking dashboards                           |

**Feed ID format:** A `Symbol` up to 32 bytes, ASCII alphanumeric + `_`. Examples: `XLM_USDC`,
`BTC_USD`. Empty feed IDs are rejected with `OracleError::InvalidFeedId`.

**Quorum rule:** A price update is only accepted into `FeedLatest` when the number of
active submissions meets `max(min_quorum, feed_quorum_override)`. Events for _individual_
submissions are emitted regardless; only the aggregated `FeedLatest` update represents consensus.

### 4.3 Treasury Events

| Event constant                | Topics           | Payload                                                      | Producer           | Consumers                       |
|-------------------------------|------------------|--------------------------------------------------------------|--------------------|---------------------------------|
| `TREASURY_SET`                | `("trs_set",)`   | `(address: Address)`                                         | `treasury-contract`| Admin tooling                   |
| `TREASURY_DEPOSIT`            | `("t_dep",)`     | `(from: Address, token: Address, amount: i128, category: Symbol)` | `treasury-contract` | Off-chain accounting           |
| `TREASURY_WITHDRAW`           | `("t_wdw",)`     | `(to: Address, token: Address, amount: i128, reason: Symbol)`| `treasury-contract`| Off-chain accounting, alerting  |
| `TREASURY_EMERGENCY_WITHDRAW` | `("t_emrg",)`    | `(to: Address, token: Address, amount: i128)`                | `treasury-contract`| Alerting (critical severity)    |

### 4.4 Payment / Escrow Events

| Event constant              | Topics              | Payload                                                                       | Producer             | Consumers          |
|-----------------------------|---------------------|-------------------------------------------------------------------------------|----------------------|--------------------|
| `PAYMENT_TRANSFER`          | `("pay_xfr",)`      | `(from: Address, to: Address, token: Address, amount: i128)`                  | `payments-contract`  | Off-chain ledger   |
| `PAYMENT_FEE`               | `("pay_fee",)`      | `(from: Address, fee_recipient: Address, amount: i128)`                       | `payments-contract`  | Off-chain ledger   |
| `PAYMENT_ESCROW_CREATED`    | `("pay_esc_c",)`    | `(escrow_id: u64, depositor: Address, beneficiary: Address, amount: i128, expiry_ledger: u32)` | `payments-contract` | Off-chain indexer |
| `PAYMENT_ESCROW_RELEASED`   | `("pay_esc_r",)`    | `(escrow_id: u64, beneficiary: Address, amount: i128)`                        | `payments-contract`  | Off-chain indexer  |
| `PAYMENT_ESCROW_REFUNDED`   | `("pay_esc_f",)`    | `(escrow_id: u64, depositor: Address, amount: i128)`                          | `payments-contract`  | Off-chain indexer  |

### 4.5 NFT Marketplace Events

| Event                        | Topics                  | Payload                                                                            | Producer         | Consumers                              |
|------------------------------|-------------------------|------------------------------------------------------------------------------------|------------------|----------------------------------------|
| `emit_nft_listed`            | `("nft", "listed")`     | `(listing_id: u64, seller: Address, collection: Address, token_id: u64, price: i128, currency: Address)` | `nft-marketplace` | Off-chain marketplace UI |
| `emit_nft_sold`              | `("nft", "sold")`       | `(listing_id: u64, buyer: Address, seller: Address, amount: i128, currency: Address)`| `nft-marketplace` | `referral-contract` (accrue trigger), off-chain indexer |
| `emit_nft_offer`             | `("nft", "offer")`      | `(offer_id: u64, buyer: Address, collection: Address, token_id: u64, price: i128)` | `nft-marketplace` | Off-chain marketplace UI |
| `emit_nft_bid`               | `("nft", "bid")`        | `(auction_id: u64, bidder: Address, amount: i128, timestamp: u64)`                 | `nft-marketplace` | Off-chain marketplace UI |
| `emit_nft_auction`           | `("nft", "auction")`    | `(auction_id: u64, seller: Address, start_price: i128, end_time: u64, type: AuctionType)` | `nft-marketplace` | Off-chain marketplace UI |
| `emit_nft_settle`            | `("nft", "settle")`     | `(auction_id: u64, winner: Address, final_price: i128)`                            | `nft-marketplace` | Off-chain indexer       |
| `emit_royalty_paid`          | `("nft", "royalty")`    | `(collection: Address, recipient: Address, amount: i128, currency: Address)`        | `nft-marketplace` | Creator dashboards       |
| `emit_collection_registered` | `("nft", "coll_reg")`   | `(collection: Address, name: Symbol)`                                              | `nft-marketplace` | Admin tooling            |
| `emit_bid_refund_credited`   | `("nft", "ref_cred")`   | `(bidder: Address, token: Address, amount: i128)`                                  | `nft-marketplace` | Bidder wallet UI         |
| `emit_bid_refund_claimed`    | `("nft", "ref_clm")`    | `(bidder: Address, token: Address, amount: i128)`                                  | `nft-marketplace` | Bidder wallet UI         |

### 4.6 Governance Events

| Event constant       | Topics                 | Payload                                                                      | Producer             | Consumers                      |
|----------------------|------------------------|------------------------------------------------------------------------------|----------------------|--------------------------------|
| `PROPOSAL_CREATED`   | `("prop_new",)`        | `(proposal_id: u64, proposer: Address, action: ProposalAction)`              | `governance-contract`| Admin dashboards               |
| `PROPOSAL_APPROVED`  | `("prop_apr",)`        | `(proposal_id: u64, approver: Address, approval_count: u32)`                 | `governance-contract`| Admin dashboards               |
| `PROPOSAL_EXECUTED`  | `("prop_exc",)`        | `(proposal_id: u64, executor: Address)`                                      | `governance-contract`| Admin dashboards, target contracts |
| `PROPOSAL_CANCELLED` | `("prop_can",)`        | `(proposal_id: u64, canceller: Address)`                                     | `governance-contract`| Admin dashboards               |
| `PROPOSAL_EXPIRED`   | `("prop_exp",)`        | `(proposal_id: u64)`                                                         | `governance-contract`| Admin dashboards               |
| `ROLE_GRANTED`       | `("role_grt",)`        | `(user: Address, role: Role)`                                                | `governance-contract`| Access-control monitors        |
| `ROLE_REVOKED`       | `("role_rvk",)`        | `(user: Address, role: Role)`                                                | `governance-contract`| Access-control monitors        |
| `PARAMETER_CHANGED`  | `("param_chg",)`       | `(key: ParameterKey, value: i128)`                                           | `governance-contract`| All contracts (config consumers) |

### 4.7 Referral Events

| Event constant        | Topics          | Payload                                              | Producer          | Consumers                          |
|-----------------------|-----------------|------------------------------------------------------|-------------------|------------------------------------|
| `REFERRER_SET`        | `("ref_set",)`  | `(wallet: Address, referrer: Address)`               | `referral-contract`| Off-chain analytics               |
| `REFERRAL_REGISTERED` | `("ref_reg",)`  | `(wallet: Address, referrer: Address)`               | `referral-contract`| Off-chain analytics               |
| `REFERRAL_ACCRUED`    | `("ref_acc",)`  | `(referrer: Address, amount: i128, tier: u32)`       | `referral-contract`| Reward dashboards                  |
| `TIER_CONFIG_SET`     | `("tier_cfg",)` | `(max_tiers: u32, tier_bps: Vec<i128>, reward_cap: i128)` | `referral-contract`| Admin tooling                 |

### 4.8 Lifecycle / Cross-Cutting Events

| Event constant          | Topics              | Payload                                                  | Producer         | Consumers             |
|-------------------------|---------------------|----------------------------------------------------------|------------------|-----------------------|
| `CONTRACT_PAUSED`       | `("paused",)`       | `(contract: Symbol, pauser: Address, timestamp: u64)`    | Any              | Alerting, UI banners  |
| `CONTRACT_RESUMED`      | `("resumed",)`      | `(contract: Symbol, pauser: Address, timestamp: u64)`    | Any              | Alerting, UI banners  |
| `CONTRACT_UPGRADED`     | `("upgraded",)`     | `(contract: Address, old_wasm: BytesN<32>, new_wasm: BytesN<32>)` | `upgradeability` | Alerting    |
| `CONTRACT_SCOPED_PAUSED`| `("sc_pause",)`     | `(scope: Symbol, caller: Address)`                       | `access-control` | Alerting              |
| `CONTRACT_SCOPED_RESUMED`| `("sc_resum",)`    | `(scope: Symbol, caller: Address)`                       | `access-control` | Alerting              |
| `COMMISSION_PAID`       | `("com_paid",)`     | `(payer: Address, recipient: Address, amount: i128)`     | Any              | Off-chain accounting  |

---

## 5. Cross-Contract Call Map

### 5.1 Runtime Invocation Table

| Caller              | Function called        | Callee                        | Trigger                                   | Required fields on callee             |
|---------------------|------------------------|-------------------------------|-------------------------------------------|---------------------------------------|
| `oracle-contract`   | `distribute_reward`    | `treasury-contract`           | Slash penalty routing                     | `token: Address, amount: i128, recipient: Address` |
| `treasury-contract` | `accrue`               | `referral-contract`           | `distribute_reward` post-credit call      | `wallet: Address, trade_amount: i128` |
| `treasury-contract` | `deposit / withdraw / harvest` | Reserve strategy contracts | `allocate_reserve / harvest_yield`   | Strategy implements `ReserveStrategy` trait |
| `referral-contract` | `distribute_reward`    | `treasury-contract`           | `claim_rewards` payout                    | `token: Address, amount: i128, recipient: Address` |
| `referral-contract` | `get_contract`         | `registry-contract`           | Treasury address fallback lookup          | `name: Symbol` → `(Address, u32)`     |
| `nft-marketplace`   | `get_latest_price`     | `oracle-contract`             | Optional price validation on listing/bid  | `feed_id: Symbol` → `FeedLatest`      |
| `nft-marketplace`   | `transfer_from / transfer` | NFT collection contract   | `buy_nft`, `settle_*_auction`, `accept_offer`, `cancel_*` | SEP-11 / SEP-41 token interface |
| `nft-marketplace`   | `transfer_from / transfer` | Currency token (SAC)      | All payment flows                         | SAC / SEP-41 `transfer`, `transfer_from` |
| `governance-contract` | `{function_name}`    | Any target contract           | `ProposalAction::SetTargetParameter` execution | Callee must expose the named function  |
| `upgradeability`    | `validate_storage / pre_upg / pst_upg` | Migration hook contracts | `propose_upgrade / execute_upgrade` | Hook must expose all three entry points |
| `aid-contract`      | `transfer / transfer_from` | Soroban token (SAC)      | `create_aid`, `claim_aid`, `refund_aid`, milestone variants | SAC `transfer` / `transfer_from` |
| `payments-contract` | `transfer / transfer_from` | Soroban token (SAC)      | All deposit, withdraw, escrow flows       | SAC `transfer` / `transfer_from`      |

### 5.2 Interface Contracts Required by Each Callee

#### `treasury-contract` — `distribute_reward` boundary

```rust
// treasury-contract public entry point
pub fn distribute_reward(
    env: Env,
    caller: Address,   // must hold TreasuryManager role
    recipient: Address,
    token: Address,
    amount: i128,      // must be > 0
) -> Result<(), Error>
```

Callers: `referral-contract` (from `claim_rewards`), `oracle-contract` (from `slash_submitter`).  
Failure behavior: returns `Error::Unauthorized` if `caller` lacks `TreasuryManager` role.
Both callers must handle this error and surface it rather than silently swallowing it.

#### `referral-contract` — `accrue` boundary

```rust
// referral-contract public entry point
pub fn accrue(
    env: Env,
    wallet: Address,   // the address whose referrer chain is walked
    trade_amount: i128,
) -> Result<(), Error>
```

Caller: `treasury-contract` (from `distribute_reward`). Called _after_ token transfer succeeds.  
Failure behavior: `Error::ConfigMissing` when `TierConfig` not set. Treasury must handle this
gracefully — a missing tier config is non-fatal and should be logged, not propagated as a treasury
failure.

#### `registry-contract` — `get_contract` boundary

```rust
// registry-contract public entry point
pub fn get_contract(
    env: Env,
    name: Symbol,      // e.g. symbol_short!("treasury")
) -> Result<(Address, u32), Error>
```

Caller: `referral-contract` (treasury fallback). Returns `Error::NotFound` when the name is not
registered. `referral-contract` must treat `NotFound` as `Error::DependencyDegraded` and log,
not panic.

#### `oracle-contract` — `get_latest_price` boundary

```rust
// oracle-contract public entry point
pub fn get_latest_price(
    env: Env,
    feed_id: Symbol,
) -> Result<FeedLatest, OracleError>
```

```rust
pub struct FeedLatest {
    pub feed_id: Symbol,
    pub price: i128,
    pub decimals: u32,
    pub timestamp: u64,
    pub submission_count: u64,
}
```

Caller: `nft-marketplace` (optional). If the oracle is not configured (`oracle_address == None`)
the marketplace skips price validation entirely. If configured and `OracleError::FeedNotFound` or
`OracleError::InsufficientQuorum` is returned, the listing or bid must be rejected with a
descriptive error.

#### `governance-contract` — `SetTargetParameter` boundary

```rust
// ProposalAction variant
SetTargetParameter(
    target: Address,    // the contract to call
    function_name: Symbol,
    key: ParameterKey,
    value: i128,
)
```

When this proposal executes, governance calls `target.function_name(key, value)`. The target
contract must expose a function matching `function_name` that accepts `(ParameterKey, i128)`.
Any target that does not expose the expected function will panic at the Soroban invocation level,
causing the proposal execution to fail and leaving the proposal in a failed state (not
auto-retried).

Known `SetTargetParameter` wiring as of this writing:

| `function_name`           | Intended target       | Effect                                    |
|---------------------------|-----------------------|-------------------------------------------|
| `set_withdrawal_limit`    | `treasury-contract`   | Updates `TreasuryWithdrawalLimit`         |
| `set_tier_config`         | `referral-contract`   | Updates tier BPS / max tiers / reward cap |
| `set_default_expiry`      | `aid-contract`        | Updates `AidDefaultExpiry`                |

---

## 6. Integration Boundary Specifications

### 6.1 `aid-contract` ↔ Token (Soroban SAC/SEP-41)

**Flow:** `create_aid` → `token.transfer_from(donor, contract, amount)` → escrow held in contract
storage → `claim_aid` → `token.transfer(contract, recipient, amount)`.

**Required fields:**
- `token`: must be a valid deployed SAC or SEP-41 contract address.
- `amount`: must be `> 0`. Enforced by `AidError::InvalidArgument`.
- `expiry_ledger`: must be `> current_ledger_sequence`. Enforced at creation.

**Allowed failures:**
- `token.transfer_from` fails (insufficient balance / allowance): `create_aid` returns the token's
  error. No state is written. Safe to retry after the donor funds their wallet.
- `token.transfer` fails during `claim_aid`: extremely unlikely if escrow balance is intact; if
  it occurs the aid record is _not_ updated to `Settled` — the claim can be retried.

### 6.2 `oracle-contract` ↔ Treasury (slash routing)

**Pre-condition:** `oracle-contract` must have `set_treasury(treasury_address)` called post-deploy.
`OracleError::TreasuryNotConfigured` (code 517) is returned from `slash_submitter` when not set.

**Flow:** `slash_submitter` deducts `penalty_amount` from `SubmitterStake(submitter)` → calls
`treasury.distribute_reward(oracle_contract, treasury, token, penalty_amount)`.

**Allowed failures:**
- Treasury call fails (e.g. treasury paused): slash is still recorded on the oracle side (stake
  deducted), but penalty funds remain locked in the oracle contract's stake pool. An admin must
  manually drain via a treasury emergency path.

### 6.3 `treasury-contract` ↔ `referral-contract` (reward accrual)

**Pre-condition:** `treasury.set_referral_contract(referral_address)` called post-deploy.

**Flow:** `treasury.distribute_reward(caller, recipient, token, amount)` → internal transfer to
`recipient` → calls `referral.accrue(recipient, amount)`.

**Allowed failures:**
- `referral.accrue` fails: treasury logs `Error::DependencyDegraded` and continues — the payment
  to `recipient` is already final. The accrual miss is not retried automatically.
- Referral contract not set: accrual step is silently skipped; the reward transfer still completes.

### 6.4 `referral-contract` ↔ `treasury-contract` (claim payout)

**Flow:** `referral.claim_rewards(referrer)` → reads `Accrued(referrer)` → clears balance →
calls `treasury.distribute_reward(referral_contract, referrer, token, amount)`.

**Re-entrancy guard:** Balance is cleared _before_ the treasury call. If the treasury call fails,
the balance is _not_ restored — this is a deliberate, safe design: the referral contract will
over-clear. Governance should remediate via a manual treasury disbursement if the treasury call
fails after balance clear.

**Fallback:** If the direct treasury address is not set, `referral-contract` calls
`registry.get_contract(symbol_short!("treasury"))` to resolve it dynamically. This prevents a
hard failure when the treasury is re-deployed at a new address.

### 6.5 `nft-marketplace` ↔ `oracle-contract` (price validation)

**Opt-in:** Only active when `oracle_address` is set via `set_oracle(oracle)`.

**Flow:** On `list_nft` or `place_bid`, marketplace calls `oracle.get_latest_price(feed_id)`.
The feed ID is derived from the currency symbol. If the oracle returns `OracleError::StaleData`
(`Error::StaleData` code 28), the listing/bid is rejected — this prevents stale-price attacks.

**Staleness rule:** Oracle maintains a `staleness_window` (seconds). Any `FeedLatest.timestamp`
older than `now - staleness_window` causes `get_latest_price` to return `OracleError::SubmissionStale`.

### 6.6 `governance-contract` ↔ Target Contracts

**Flow:** Multi-sig proposal with `SetTargetParameter(target, fn, key, val)` → accumulate M
approvals → `execute` → Soroban cross-contract call to `target.fn(key, val)`.

**Required approval math:**
```
required = max(threshold, ceil(active_admin_count × quorum_bps / 10_000))
```

**Allowed failures on execute:**
- Target function does not exist → Soroban panics → proposal status remains `Pending` (not
  `Executed`). An admin should cancel the proposal (`ProposalStatus::Cancelled`) and fix the
  target contract.
- Target returns an error → same outcome; proposal not marked executed.

**Expiry:** Proposals expire after `expires_at` ledger timestamp. Expired proposals return
`Error::ProposalExpired` on `execute`. Re-submission is required.

### 6.7 `upgradeability` ↔ Migration Hooks

**Migration hook interface** (must be implemented by any hook contract):

```rust
// Required entry points on hook contract
fn validate_storage(target: Address) -> Result<(), Error>  // pre-proposal check
fn pre_upg(old_version: u32, new_version: u32) -> Result<(), Error>  // before WASM swap
fn pst_upg(old_version: u32, new_version: u32) -> Result<(), Error>  // after WASM swap
```

**Timelock rule:** `execute_upgrade` can only be called after `created_at + timelock_delay_secs`.

**Allowed failures:**
- `validate_storage` fails → proposal rejected; safe to resubmit.
- `pre_upg` fails → upgrade aborted; WASM not swapped; state unchanged.
- `pst_upg` fails → WASM swap already applied; state is in an inconsistent migration state.
  A manual rollback via `manual_rollback()` is required (see §10.2).

---

## 7. Version & Schema Rules

### 7.1 Event Payload Versioning

Events are identified by their topic tuple. **Breaking changes** require a new topic (not
backward-compatible):

| Change type                       | Classification | Action required                                |
|-----------------------------------|---------------|------------------------------------------------|
| Add optional field to payload     | Non-breaking  | Update emitter; consumers ignore unknown fields|
| Remove or rename a field          | Breaking      | New topic symbol; deprecation notice; migration guide |
| Change a field type               | Breaking      | New topic symbol                               |
| Add a new event topic             | Non-breaking  | Document in this file                          |

### 7.2 Storage Schema Versioning (`aid-contract`)

The `StorageSchemaVersion` instance key tracks the on-disk schema. The current version is
`shared::storage_version::CURRENT_STORAGE_SCHEMA_VERSION`.

Upgrade path:
1. Increment `CURRENT_STORAGE_SCHEMA_VERSION` in `shared::storage_version`.
2. Add new `LegacyXxx` / `CurrentXxx` struct pair in `shared::compat`.
3. Implement `migrate_vN_to_vNplus1` and `downgrade_vNplus1_to_vN`.
4. Update `AidContract::upgrade_storage_schema` to call the new migration function.
5. Deploy and call `upgrade_storage_schema(admin)` — this is the only entry point that advances
   the stored version; it is idempotent once the version matches.

### 7.3 Contract WASM Versioning (`upgradeability`)

Every registered contract has a `VersionInfo { version: u32, wasm_hash: BytesN<32>, deployed_at: u64 }`.
Version numbers must be monotonically increasing. Attempting to register the same WASM hash as a
no-op upgrade returns `Error::NoChangeDetected`.

### 7.4 Registry Versioning

`registry-contract` stores a `version: u32` per named contract and a full `get_version_history`.
Callers that need a specific minimum version should read `get_contract(name)` and validate the
returned version before using the address.

### 7.5 `shared::errors::Error` Stability

Existing numeric codes are **frozen** — removing or renumbering a code is a breaking change
affecting every contract and every off-chain system that parses error codes. New codes may be
added to any open range with a PR that updates this document.

---

## 8. Failure Modes & Allowed Failure Behavior

### 8.1 Paused Contracts

Any contract guarded by `shared::storage::is_paused()` returns `Error::ContractPaused` (code 5)
on all state-changing operations while paused. Read-only queries are not affected.

**Recovery:** Admin or Pauser-role holder calls `set_paused(false)` / `resume(scope)`.

### 8.2 Stale Oracle Data

`nft-marketplace` rejects listings and bids when the oracle feed is outside the staleness window.

**Recovery:** Oracle submitters must post a fresh price before the marketplace resumes accepting
operations on that currency pair. If the oracle is permanently unavailable, governance can call
`set_oracle(none_address)` to disable price validation and allow the market to continue.

### 8.3 Treasury Unavailable During Referral Claim

If `treasury.distribute_reward` panics or returns an error during `referral.claim_rewards`, the
referral balance has already been cleared (§6.4). The referrer's accrued balance is lost from the
contract's perspective.

**Detection:** Off-chain indexers will see `REFERRAL_ACCRUED` events with no matching treasury
`TREASURY_WITHDRAW` event within the same ledger.

**Recovery:** Governance raises a `SetTargetParameter` proposal or treasury manager performs a
manual `withdraw` to the affected referrer address, using the off-chain audit trail as evidence.

### 8.4 `post_upg` Migration Hook Failure

If the post-upgrade hook panics (§6.7), the new WASM is live but the migration data transformation
has not completed. The contract is in an inconsistent state.

**Detection:** `emit_migration_hook_set` and `emit_upgrade_executed` events will be present but
`pst_upg` will have emitted a failure event or the ledger will show a Soroban invocation trap.

**Recovery:** See §10.2 (Rollback procedure).

### 8.5 Aid Escrow Token Transfer Failure

If the SAC `transfer` call inside `claim_aid` fails (e.g. contract-level token freeze), the aid
record status is **not** updated. The recipient can retry `claim_aid` after the token issue
is resolved, provided the `expiry_ledger` has not passed.

### 8.6 Insufficient Quorum in Oracle

`get_latest_price` returns `OracleError::InsufficientQuorum` (512) when fewer than `min_quorum`
active submissions exist for a feed. Consumers must handle this as a temporary degradation, not a
permanent error.

**Recovery:** Register additional submitters via `register_submitter`. The feed becomes available
once the quorum threshold is met.

### 8.7 Governance Proposal Expiry

Proposals expire at `expires_at` ledger timestamp. Expiry is lazy (not enforced by a cron) — it
is checked at `execute` time. Expired proposals must be re-submitted.

### 8.8 NFT Auction — Auto-Extension Race

If two bids arrive in the same ledger within the `auto_extension_window`, both will see the same
`end_time` before either extends it. The Soroban runtime serializes transactions within a ledger,
so the second bid will read the already-extended `end_time` and apply a second extension only if
still within the window. This is correct behavior, not a bug.

---

## 9. Operational Edge Cases

### 9.1 Aid Expiry Window vs. Ledger Sequence

Aid records store `expiry_ledger` as a Stellar **ledger sequence number**, not a UNIX timestamp.
Off-chain systems that display expiry times must map ledger sequence to approximate wall-clock time
using the Horizon API (`/ledgers/{sequence}`). The default expiry is configured in seconds
(`default_expiry_secs`) but is converted to a ledger sequence at creation time using the current
ledger's close time and the expected 5-second ledger interval.

**Edge case:** Network congestion can shift the wall-clock time of a given ledger sequence.
Recipients should be notified that expiry is sequence-based, not time-based, and should claim
with a margin before the displayed deadline.

### 9.2 Referral Vanity Code Conflicts

`referral-contract` allows users to register vanity codes (`register_referral_code`). Two users
racing to claim the same code in the same ledger will serialize; only one will succeed. No partial
state is left.

### 9.3 Oracle Nonce Replay Prevention

Each `submit_price` call requires a `nonce: u64` that must be strictly greater than the previous
nonce for the same `(submitter, feed_id)` pair. This prevents relay attacks replaying old signed
submissions. Off-chain submission pipelines must track the current nonce via `get_price_history`.

### 9.4 NFT Auction Self-Bid Prevention

`place_bid` rejects a bid from the current auction seller. The `MarketError::SelfBid` error is
returned. Multi-wallet collusion (seller bidding from another wallet) is not detectable on-chain.

### 9.5 Governance Batch Proposal Atomicity

`ProposalAction::Batch(Vec<ProposalAction>)` executes multiple actions atomically. If any
sub-action fails, the entire batch is rolled back by Soroban's transaction atomicity. The proposal
status is not marked `Executed`. The proposer should diagnose the failing sub-action, cancel the
batch proposal, and resubmit.

### 9.6 Treasury Velocity Rate Limiting

`treasury-contract` enforces per-token velocity limits (`set_velocity_limit`): a maximum amount
withdrawable within a rolling time window. Withdrawals that would exceed the limit return
`Error::WithdrawalLimitExceeded`. This is an operational control, not a security guarantee — an
admin holding `TreasuryManager` role can reset the velocity state.

### 9.7 Pending Bid Refunds — Pull Pattern

When an English auction bidder is outbid, their funds are **not** returned inline. They accumulate
in `PendingRefund(bidder, token)` persistent storage. The bidder must call `claim_bid_refund` to
withdraw. Unclaimed refunds do not expire. Off-chain UI must display pending refund balances.

### 9.8 Search Index Repair

`aid-contract` maintains a derived `SearchIndex` for discovery. If the index becomes inconsistent
(e.g. due to a storage TTL eviction), `repair_search_index(admin)` rebuilds it from canonical
`Aid(id)` records. The function is idempotent and safe to call at any time.

---

## 10. Rollback & Recovery Procedures

### 10.1 Aid Schema Rollback

`shared::compat::downgrade_v2_to_v1` provides the downgrade function. However, in production:

1. Schema downgrades are **destructive** if any V2-only fields have been written.
2. The safe approach is to redeploy a V1-capable contract version via `upgradeability`, not
   to call `downgrade` on live records.
3. Before any schema upgrade, run `validate_storage_schema(env)` to confirm all records are
   on the expected version.

### 10.2 WASM Upgrade Rollback

`upgradeability` stores a `StateSnapshot` and `RollbackInfo` for every registered contract.

**Procedure:**
1. Detect failure via `("upgraded")` event + post-upgrade hook failure event.
2. Confirm the current WASM hash via `get_wasm_hash(contract_id)`.
3. Call `upgradeability.manual_rollback(caller, contract_id)` — this re-applies the previous
   `RollbackInfo.target_wasm_hash` to the target contract.
4. Verify by calling a known stable entry point on the target contract.
5. Open a governance proposal to re-attempt the upgrade with a fixed migration hook.

**Constraint:** `manual_rollback` requires the `Upgrader` role. It does not re-run `pre_upg`/`pst_upg`.

### 10.3 Treasury — Emergency Drain

If the treasury is compromised or a bug is discovered:

1. Governance multi-sig approves `ProposalAction::Pause` for the treasury.
2. A `TreasuryManager` calls `emergency_withdraw(caller, token, safe_address, amount)`.
   This emits `TREASURY_EMERGENCY_WITHDRAW` (critical severity alert).
3. Funds land at `safe_address` (a cold wallet or a freshly deployed replacement treasury).
4. Governance coordinates a redeployment and calls `treasury.set_referral_contract` and
   `oracle.set_treasury` with the new address.
5. Registry entry is updated via `registry.set_contract("treasury", new_address, new_version)`.

### 10.4 Governance Admin Set Compromise

If one or more governance admin keys are compromised:

1. The remaining non-compromised admins must hold >= `threshold` keys to form a quorum.
2. Propose and execute `ProposalAction::RevokeRole(compromised_address, Role::Admin)`.
3. Follow with `ProposalAction::GrantRole(replacement_address, Role::Admin)` if needed.
4. If quorum cannot be formed, a protocol-level emergency path (out-of-band multi-sig on the
   Stellar network layer) must be used — there is no on-chain recovery without quorum.

### 10.5 Referral Balance Stuck (§8.3 Recovery)

1. Off-chain: identify affected referrer and amount from `REFERRAL_ACCRUED` events with no
   matching `TREASURY_WITHDRAW`.
2. A `TreasuryManager` calls `treasury.withdraw(manager, token, amount, symbol_short!("ref_remediation"))`.
   This emits `TREASURY_WITHDRAW` for audit trail.
3. Manually transfer the withdrawn amount to the referrer via a signed Stellar transaction.
4. Update the off-chain referral ledger to mark the balance as settled.

---

## 11. Public API Compatibility Guarantees

### 11.1 Stable Entry Points (no breaking changes without migration plan)

The following functions are used by multiple contracts or by the off-chain SDK and must not have
their signature changed without a versioned migration plan:

| Contract            | Stable entry point            | Consumers                                |
|---------------------|-------------------------------|------------------------------------------|
| `treasury-contract` | `distribute_reward`           | `oracle-contract`, `referral-contract`   |
| `referral-contract` | `accrue`                      | `treasury-contract`                      |
| `registry-contract` | `get_contract`                | `referral-contract`                      |
| `oracle-contract`   | `get_latest_price`            | `nft-marketplace`                        |
| `aid-contract`      | `create_aid`, `claim_aid`, `refund_aid` | Off-chain SDK, indexers         |
| `governance-contract` | `propose`, `approve`, `execute` | Admin tooling, multi-sig wallets      |

**Rule:** Adding a new parameter to any of these functions is a breaking change. New optional
behavior must be introduced via a new entry point (e.g. `create_aid_v2`) and the old entry point
must be preserved for at least one release cycle.

### 11.2 Token Interface Compatibility

All contracts that interact with tokens assume the **Soroban SAC / SEP-41** interface. Specifically:
- `transfer(from: Address, to: Address, amount: i128)`
- `transfer_from(spender: Address, from: Address, to: Address, amount: i128)`

Any token used with these contracts must expose both functions. Non-standard tokens that deviate
from this interface will cause runtime panics.

### 11.3 `shared::errors::Error` Frozen Codes

All existing numeric codes in `shared::errors::Error` are frozen. See §7.5.

### 11.4 `ParameterKey` Stability

`governance-contract::ParameterKey` variants map 1:1 to entry points on other contracts
(§5.2 `SetTargetParameter` table). Adding a new variant is non-breaking. Removing or renaming
a variant breaks any pending governance proposals that reference that key.

---

## Appendix A: Quick Reference — Event Topic Symbols

All `symbol_short!` values used as event topics across the workspace:

```
"aid_crt"  "aid_clm"  "aid_stl"  "aid_ref"
"com_paid" "ref_acc"  "ref_set"  "tier_cfg"
"trs_set"  "t_dep"    "t_wdw"    "t_emrg"
"param_chg" "paused"  "resumed"  "upgraded"
"sc_pause" "sc_resum" "sc_set"   "ref_reg"
"prop_new" "prop_apr" "prop_exc" "prop_can" "prop_exp"
"role_grt" "role_rvk"
"pay_xfr"  "pay_fee"  "pay_esc_c" "pay_esc_r" "pay_esc_f"
"imp_sim"  "imp_cmt"  "imp_fail"
"evt_init" "evt_act"  "evt_perm"

Oracle contract (two-part topics):
("oracle", "sub_reg") ("oracle", "sub_del") ("oracle", "price")
("oracle", "stale")   ("oracle", "staked")  ("oracle", "slashed")
("oracle", "unbond")  ("oracle", "withdrawn")

NFT Marketplace (two-part topics):
("nft", "listed") ("nft", "sold")    ("nft", "offer")  ("nft", "bid")
("nft", "auction") ("nft", "settle") ("nft", "royalty") ("nft", "coll_reg")
("nft", "ref_cred") ("nft", "ref_clm")
```

## Appendix B: Error Code Master Table

See `shared/src/errors.rs` for the canonical source. This appendix is informational.

| Code  | Name                         | Relevant contracts               |
|-------|------------------------------|----------------------------------|
| 1     | Unauthorized                 | All                              |
| 2     | NotFound                     | All                              |
| 3     | InvalidAmount                | aid, treasury, payments          |
| 4     | Overflow                     | All                              |
| 5     | ContractPaused               | All                              |
| 6     | Expired                      | aid, payments                    |
| 7     | AlreadyClaimed               | aid                              |
| 8     | InsufficientBalance          | treasury, payments               |
| 9     | WithdrawalLimitExceeded      | treasury                         |
| 10    | InvalidArgument              | All                              |
| 12    | ProposalNotFound             | governance                       |
| 13    | AlreadyApproved              | governance                       |
| 14    | BelowThreshold               | governance                       |
| 15    | AlreadyExecuted              | governance                       |
| 19    | AlreadyInitialized           | All                              |
| 28    | StaleData                    | oracle, nft-marketplace          |
| 41    | DependencyDegraded           | referral, treasury               |
| 100   | AidError::Unauthorized       | aid-contract                     |
| 500   | OracleError::SubmitterNotAuthorized | oracle-contract           |
| 512   | OracleError::InsufficientQuorum | oracle-contract               |
| 517   | OracleError::TreasuryNotConfigured | oracle-contract             |
| 700   | PaymentInvalidAmount         | payments-contract                |
| 702   | PaymentEscrowNotFound        | payments-contract                |
| 900   | ContractNotRegistered        | upgradeability                   |
| 950   | InvalidTransition            | aid-contract                     |
| 1000  | ListingNotFound              | nft-marketplace                  |
