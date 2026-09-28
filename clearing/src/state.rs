//! Deterministic clearing state machine.
//!
//! [`State`] holds accounts, per-market [`Instrument`]s, and [`MarketGlobals`].
//! [`State::apply`] applies one [`Tx`] transactionally: it dispatches through
//! [`crate::settlement::handler`], and a rejected tx rolls back the touched
//! accounts. Adding an instrument type does not require edits here.
//!
//! Containers are ordered (`BTreeMap`), arithmetic is checked, and there is no
//! wall-clock or RNG. The same `Tx` sequence on a fresh `State` always yields
//! the same `State`.

use std::collections::{BTreeMap, BTreeSet};

use crate::account::Account;
use crate::auth::{Ed25519PubKey, Side, TradeAuth};
use crate::commitment::{Hash, encode_matcher_msg, encode_order, order_id};
use crate::error::SettlementError;
use crate::id::{AccountId, Amount, AssetId, MarketId};
use crate::instrument::{Instrument, MarketGlobals};
use crate::settlement::{Fill, Ledger, handler};
use crate::tx::Tx;

/// Which accounts a successfully-applied [`Tx`] changed. The commitment layer
/// updates only these Merkle leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDelta {
    pub changed: Vec<AccountId>,
}

/// The clearing state: accounts, registered instruments (by market), and
/// per-market globals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    accounts: BTreeMap<AccountId, Account>,
    instruments: BTreeMap<MarketId, Instrument>,
    globals: BTreeMap<MarketId, MarketGlobals>,
    /// Deposit nonces already credited. A deposit is never double-credited.
    /// Not in the account tree (the root commits accounts only).
    applied_deposits: BTreeSet<u64>,
    /// The operator/matcher ed25519 key. Every trade must carry a matcher
    /// signature under this key; while `None`, no authenticated trade can pass.
    /// This is trusted verifier configuration (the exchange's own key), not
    /// witness data: the prover receives it from [`crate::ExecutingProver`] and
    /// the on-chain contract from its own config — so a witness can't disable auth
    /// by lying about it.
    operator_key: Option<Ed25519PubKey>,
    /// Monotonic batch height, for order expiry. Supplied by the verifier
    /// (contract counter) at prove time; on the live state, advanced per batch by
    /// the engine. Not committed in the account tree — a trusted verifier input.
    batch_height: u64,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the instrument a market trades, initializing default globals.
    /// (v0 admin path; markets are static.)
    pub fn register_market(&mut self, market: MarketId, instrument: Instrument) {
        self.instruments.insert(market, instrument);
        self.globals.entry(market).or_default();
    }

    /// Replace a market's globals (funding tick, mark price, …). Unused by spot.
    pub fn set_globals(&mut self, market: MarketId, globals: MarketGlobals) {
        self.globals.insert(market, globals);
    }

    /// Register the operator/matcher key (admin path). Every trade's matcher
    /// signature is verified against this.
    pub fn set_operator_key(&mut self, key: Ed25519PubKey) {
        self.operator_key = Some(key);
    }

    /// The registered operator/matcher key, if any.
    pub fn operator_key(&self) -> Option<Ed25519PubKey> {
        self.operator_key
    }

    /// The current batch height (used for order expiry).
    pub fn batch_height(&self) -> u64 {
        self.batch_height
    }

    /// Set the batch height (the engine advances this once per batch).
    pub fn set_batch_height(&mut self, height: u64) {
        self.batch_height = height;
    }

    /// Cumulative base already filled against `account`'s order `id` (zero if
    /// untouched). Fills live in the account leaf (committed + re-verified).
    pub fn order_filled(&self, account: AccountId, id: &Hash) -> Amount {
        self.accounts
            .get(&account)
            .map(|a| a.order_filled(id))
            .unwrap_or(Amount::ZERO)
    }

    /// Trading key registered to `account`, or `MissingTradingKey`.
    fn trading_key_of(&self, account: AccountId) -> Result<Ed25519PubKey, SettlementError> {
        self.accounts
            .get(&account)
            .and_then(|a| a.trading_key())
            .ok_or(SettlementError::MissingTradingKey { account })
    }

    /// Authorize a matched trade: verify both users' order signatures and the
    /// matcher signature, that the orders are structurally consistent with the
    /// fill, unexpired, price-respecting, and not over-filled. Read-only; returns
    /// the two order ids so the caller can record the fill after settlement
    /// succeeds. This is the rule the executing prover / zkVM guest re-runs.
    pub(crate) fn check_trade_auth(
        &self,
        market: MarketId,
        fill: &Fill,
        auth: &TradeAuth,
    ) -> Result<(Hash, Hash), SettlementError> {
        let buy = &auth.buy.order;
        let sell = &auth.sell.order;

        // 1. The two orders must be consistent with the fill and each other.
        if buy.market != market
            || sell.market != market
            || buy.side != Side::Buy
            || sell.side != Side::Sell
            || buy.account != fill.buyer
            || sell.account != fill.seller
        {
            return Err(SettlementError::OrderMismatch);
        }

        // 2. Positive fill (settlement also checks, but authorization is the gate).
        if fill.base_amount.0 <= 0 || fill.quote_amount.0 <= 0 {
            return Err(SettlementError::NonPositiveQuantity);
        }

        // 3. Both users signed their orders; the matcher signed the fill.
        let buyer_key = self.trading_key_of(fill.buyer)?;
        let seller_key = self.trading_key_of(fill.seller)?;
        if !crate::auth::verify(&buyer_key, &encode_order(buy), &auth.buy.sig) {
            return Err(SettlementError::InvalidOrderSignature);
        }
        if !crate::auth::verify(&seller_key, &encode_order(sell), &auth.sell.sig) {
            return Err(SettlementError::InvalidOrderSignature);
        }
        let operator_key = self
            .operator_key
            .ok_or(SettlementError::InvalidMatcherSignature)?;
        let buy_id = order_id(buy);
        let sell_id = order_id(sell);
        let matcher_msg = encode_matcher_msg(market, &buy_id, &sell_id, fill);
        if !crate::auth::verify(&operator_key, &matcher_msg, &auth.matcher_sig) {
            return Err(SettlementError::InvalidMatcherSignature);
        }

        // 4. Neither order expired.
        if buy.expiry < self.batch_height || sell.expiry < self.batch_height {
            return Err(SettlementError::OrderExpired);
        }

        // 5. Price: buyer pays at most its limit; seller receives at least its
        //    limit. Compare `quote` to `limit_price * base` to avoid division.
        if fill.quote_amount > buy.limit_price.checked_mul(fill.base_amount)? {
            return Err(SettlementError::PriceViolation);
        }
        if fill.quote_amount < sell.limit_price.checked_mul(fill.base_amount)? {
            return Err(SettlementError::PriceViolation);
        }

        // 6. No over-fill, cumulatively across (async) fills of a resting order.
        //    Prior fills come from the (committed) buyer/seller account leaves.
        if self
            .order_filled(fill.buyer, &buy_id)
            .checked_add(fill.base_amount)?
            > buy.base_amount
        {
            return Err(SettlementError::OrderOverfilled);
        }
        if self
            .order_filled(fill.seller, &sell_id)
            .checked_add(fill.base_amount)?
            > sell.base_amount
        {
            return Err(SettlementError::OrderOverfilled);
        }

        Ok((buy_id, sell_id))
    }

    /// The instrument a market trades, if registered.
    pub fn instrument(&self, market: MarketId) -> Option<&Instrument> {
        self.instruments.get(&market)
    }

    /// Build a state seeded with the given accounts + markets, for **re-executing
    /// a single batch** in isolation (a prover / zkVM guest). `applied_deposits`
    /// starts empty — the batch's deposits are applied for the first time — and
    /// per-market globals default. The result of applying the batch here must
    /// match what the live state produced; that equivalence is what the executing
    /// prover checks.
    pub fn for_replay(
        accounts: impl IntoIterator<Item = (AccountId, Account)>,
        markets: impl IntoIterator<Item = (MarketId, Instrument)>,
        operator_key: Option<Ed25519PubKey>,
        batch_height: u64,
    ) -> Self {
        let mut s = Self::new();
        for (market, instrument) in markets {
            s.register_market(market, instrument);
        }
        for (id, account) in accounts {
            s.accounts.insert(id, account);
        }
        // Seed the *trusted verifier* auth context (matcher key + expiry height)
        // so replay re-verifies trades identically to the live apply. Prior fills
        // are NOT seeded here — they ride in the account leaves (`accounts`).
        s.operator_key = operator_key;
        s.batch_height = batch_height;
        s
    }

    /// Read-only view of an account (`None` if it holds nothing).
    pub fn account(&self, id: AccountId) -> Option<&Account> {
        self.accounts.get(&id)
    }

    /// Convenience: an account's balance of `asset` (zero if absent).
    pub fn balance(&self, account: AccountId, asset: AssetId) -> Amount {
        self.accounts
            .get(&account)
            .map(|a| a.balance(asset))
            .unwrap_or(Amount::ZERO)
    }

    /// Iterate accounts in canonical (id-sorted) order — for the commitment.
    pub fn accounts(&self) -> impl Iterator<Item = (&AccountId, &Account)> {
        self.accounts.iter()
    }

    /// Apply one transaction atomically. On success, returns the set of changed
    /// accounts; on rejection, the state is unchanged and the reason is
    /// returned.
    pub fn apply(&mut self, tx: &Tx) -> Result<StateDelta, SettlementError> {
        let touched = tx.touched_accounts();
        // Snapshot exactly the accounts this tx can touch (Some = prior value,
        // None = did not exist), so we can restore on rejection.
        let snapshot: Vec<(AccountId, Option<Account>)> = touched
            .iter()
            .map(|a| (*a, self.accounts.get(a).cloned()))
            .collect();

        match self.apply_inner(tx) {
            Ok(()) => {
                // Prune any touched account that ended up empty, so "empty" and
                // "absent" are the same state (canonical for the commitment).
                for a in &touched {
                    if self.accounts.get(a).is_some_and(Account::is_empty) {
                        self.accounts.remove(a);
                    }
                }
                Ok(StateDelta { changed: touched })
            }
            Err(e) => {
                for (a, prev) in snapshot {
                    match prev {
                        Some(acc) => {
                            self.accounts.insert(a, acc);
                        }
                        None => {
                            self.accounts.remove(&a);
                        }
                    }
                }
                Err(e)
            }
        }
    }

    fn apply_inner(&mut self, tx: &Tx) -> Result<(), SettlementError> {
        match tx {
            Tx::Deposit {
                account,
                asset,
                amount,
                nonce,
                owner,
                trading_key,
            } => {
                // Replay protection: credit a given deposit nonce at most once.
                if self.applied_deposits.contains(nonce) {
                    return Err(SettlementError::DuplicateDeposit(*nonce));
                }
                self.credit(*account, *asset, *amount)?;
                self.accounts
                    .entry(*account)
                    .or_default()
                    .set_l1_owner(*owner)?;
                // Register the trading key if the deposit carries one (the first
                // deposit for an account). Idempotent to the same key; a
                // conflicting key rejects the whole tx (rolls back the credit).
                if let Some(key) = trading_key {
                    self.accounts
                        .entry(*account)
                        .or_default()
                        .set_trading_key(*key)?;
                }
                self.applied_deposits.insert(*nonce);
                Ok(())
            }
            Tx::Withdraw {
                account,
                asset,
                amount,
            } => {
                if self
                    .accounts
                    .get(account)
                    .is_some_and(|a| a.l1_owner().is_none())
                {
                    return Err(SettlementError::OwnerMismatch);
                }
                self.debit(*account, *asset, *amount)
            }
            Tx::Trade { market, fill, auth } => {
                // Authorization gate. Enforced whenever an operator key is
                // registered — which, in production, is always: the contract sets
                // it at genesis. The no-operator-key path (auth skipped) exists
                // only for lower-level settlement/commitment tests. On success we
                // hold the two order ids to record the fill *after* settlement.
                let recorded = if self.operator_key.is_some() {
                    let auth = auth
                        .as_ref()
                        .ok_or(SettlementError::InvalidMatcherSignature)?;
                    Some(self.check_trade_auth(*market, fill, auth)?)
                } else {
                    None
                };

                // Clone the (small) descriptor/globals so the immutable lookups
                // release their borrow before settlement takes `self` mutably as
                // the ledger.
                let instrument = self
                    .instruments
                    .get(market)
                    .ok_or(SettlementError::UnknownMarket(*market))?
                    .clone();
                let globals = self.globals.get(market).cloned().unwrap_or_default();
                handler(instrument.kind).apply_fill(&instrument, &globals, self, fill)?;

                // Record the fill against each party's order (in their account
                // leaf) only after settlement succeeded — so a rejected fill
                // leaves the accounting alone, and the transactional snapshot of
                // the touched accounts rolls it back on any later error.
                if let Some((buy_id, sell_id)) = recorded {
                    self.accounts
                        .entry(fill.buyer)
                        .or_default()
                        .record_order_fill(buy_id, fill.base_amount)?;
                    self.accounts
                        .entry(fill.seller)
                        .or_default()
                        .record_order_fill(sell_id, fill.base_amount)?;
                }
                Ok(())
            }
        }
    }
}

/// The state machine *is* the ledger settlement acts through.
impl Ledger for State {
    fn credit(
        &mut self,
        account: AccountId,
        asset: AssetId,
        amount: Amount,
    ) -> Result<(), SettlementError> {
        self.accounts
            .entry(account)
            .or_default()
            .credit(asset, amount)
    }

    fn debit(
        &mut self,
        account: AccountId,
        asset: AssetId,
        amount: Amount,
    ) -> Result<(), SettlementError> {
        self.accounts
            .entry(account)
            .or_default()
            .debit(account, asset, amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::L1Address;
    use crate::instrument::SettlementKind;
    use crate::settlement::Fill;
    use uuid::Uuid;

    const USDC: AssetId = AssetId(0);
    const BTC: AssetId = AssetId(1);

    fn buyer() -> AccountId {
        AccountId(Uuid::from_u128(0xB))
    }
    fn seller() -> AccountId {
        AccountId(Uuid::from_u128(0x5))
    }
    fn buyer_owner() -> L1Address {
        L1Address([1u8; 32])
    }
    fn seller_owner() -> L1Address {
        L1Address([2u8; 32])
    }
    fn owner_of(account: AccountId) -> L1Address {
        if account == buyer() {
            buyer_owner()
        } else if account == seller() {
            seller_owner()
        } else {
            L1Address([9u8; 32])
        }
    }
    fn market() -> MarketId {
        MarketId(Uuid::from_u128(0xA1))
    }

    fn with_btc_usdc() -> State {
        let mut s = State::new();
        s.register_market(
            market(),
            Instrument {
                id: crate::id::InstrumentId(1),
                kind: SettlementKind::SpotSwap,
                base: BTC,
                quote: USDC,
                base_scale: 8,
                quote_scale: 6,
            },
        );
        s
    }

    /// Build a deposit with a process-unique nonce, so repeated helper calls in
    /// one test never collide on the replay-protection set.
    fn deposit(account: AccountId, asset: AssetId, amount: i128) -> Tx {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NONCE: AtomicU64 = AtomicU64::new(0);
        Tx::Deposit {
            account,
            asset,
            amount: Amount(amount),
            nonce: NONCE.fetch_add(1, Ordering::Relaxed),
            owner: owner_of(account),
            trading_key: None,
        }
    }

    #[test]
    fn duplicate_deposit_nonce_rejected() {
        let mut s = State::new();
        let dep = Tx::Deposit {
            account: buyer(),
            asset: USDC,
            amount: Amount(100),
            nonce: 7,
            owner: buyer_owner(),
            trading_key: None,
        };
        s.apply(&dep).unwrap();
        assert_eq!(s.balance(buyer(), USDC), Amount(100));
        // Replaying the same nonce is rejected and does not double-credit.
        assert_eq!(s.apply(&dep), Err(SettlementError::DuplicateDeposit(7)));
        assert_eq!(s.balance(buyer(), USDC), Amount(100));
    }

    #[test]
    fn first_deposit_registers_trading_key() {
        use crate::auth::Ed25519PubKey;
        let mut s = State::new();
        let key = Ed25519PubKey([9u8; 32]);

        s.apply(&Tx::Deposit {
            account: buyer(),
            asset: USDC,
            amount: Amount(100),
            nonce: 0,
            owner: buyer_owner(),
            trading_key: Some(key),
        })
        .unwrap();
        assert_eq!(s.account(buyer()).unwrap().trading_key(), Some(key));
        assert_eq!(s.account(buyer()).unwrap().l1_owner(), Some(buyer_owner()));

        // A later deposit with the same key is fine; balance keeps growing.
        s.apply(&Tx::Deposit {
            account: buyer(),
            asset: USDC,
            amount: Amount(50),
            nonce: 1,
            owner: buyer_owner(),
            trading_key: Some(key),
        })
        .unwrap();
        assert_eq!(s.balance(buyer(), USDC), Amount(150));

        // A deposit trying to *change* the key is rejected and rolls back (no
        // credit applied).
        let conflict = Tx::Deposit {
            account: buyer(),
            asset: USDC,
            amount: Amount(1000),
            nonce: 2,
            owner: buyer_owner(),
            trading_key: Some(Ed25519PubKey([1u8; 32])),
        };
        assert_eq!(
            s.apply(&conflict),
            Err(SettlementError::KeyAlreadyRegistered)
        );
        assert_eq!(s.balance(buyer(), USDC), Amount(150));
        assert_eq!(s.account(buyer()).unwrap().trading_key(), Some(key));
    }

    #[test]
    fn deposit_binds_owner_and_rejects_mismatch() {
        let mut s = State::new();
        s.apply(&Tx::Deposit {
            account: buyer(),
            asset: USDC,
            amount: Amount(100),
            nonce: 0,
            owner: buyer_owner(),
            trading_key: None,
        })
        .unwrap();
        assert_eq!(s.account(buyer()).unwrap().l1_owner(), Some(buyer_owner()));

        let conflict = Tx::Deposit {
            account: buyer(),
            asset: USDC,
            amount: Amount(50),
            nonce: 1,
            owner: seller_owner(),
            trading_key: None,
        };
        assert_eq!(s.apply(&conflict), Err(SettlementError::OwnerMismatch));
        assert_eq!(s.balance(buyer(), USDC), Amount(100));
        assert_eq!(s.account(buyer()).unwrap().l1_owner(), Some(buyer_owner()));
    }

    #[test]
    fn withdraw_without_owner_is_rejected() {
        let mut funded = Account::new();
        funded.credit(USDC, Amount(100)).unwrap();
        let mut s = State::for_replay([(buyer(), funded)], [], None, 0);
        assert_eq!(
            s.apply(&Tx::Withdraw {
                account: buyer(),
                asset: USDC,
                amount: Amount(10),
            }),
            Err(SettlementError::OwnerMismatch)
        );
        assert_eq!(s.balance(buyer(), USDC), Amount(100));
    }

    #[test]
    fn deposit_then_withdraw() {
        let mut s = State::new();
        s.apply(&deposit(buyer(), USDC, 100)).unwrap();
        assert_eq!(s.balance(buyer(), USDC), Amount(100));
        s.apply(&Tx::Withdraw {
            account: buyer(),
            asset: USDC,
            amount: Amount(40),
        })
        .unwrap();
        assert_eq!(s.balance(buyer(), USDC), Amount(60));
    }

    #[test]
    fn withdraw_to_zero_prunes_account() {
        let mut s = State::new();
        s.apply(&deposit(buyer(), USDC, 50)).unwrap();
        s.apply(&Tx::Withdraw {
            account: buyer(),
            asset: USDC,
            amount: Amount(50),
        })
        .unwrap();
        assert!(s.account(buyer()).is_none());
    }

    #[test]
    fn trade_settles_between_two_accounts() {
        let mut s = with_btc_usdc();
        s.apply(&deposit(buyer(), USDC, 1000)).unwrap();
        s.apply(&deposit(seller(), BTC, 5)).unwrap();

        let delta = s
            .apply(&Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: buyer(),
                    seller: seller(),
                    base_amount: Amount(5),
                    quote_amount: Amount(1000),
                },
                auth: None,
            })
            .unwrap();

        assert_eq!(s.balance(buyer(), BTC), Amount(5));
        assert_eq!(s.balance(seller(), USDC), Amount(1000));
        // both base and quote fully swapped => both original holdings are gone
        assert_eq!(s.balance(buyer(), USDC), Amount::ZERO);
        assert_eq!(s.balance(seller(), BTC), Amount::ZERO);
        assert_eq!(delta.changed, vec![buyer(), seller()]);
    }

    #[test]
    fn unknown_market_rejected() {
        let mut s = State::new(); // no markets registered
        let err = s
            .apply(&Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: buyer(),
                    seller: seller(),
                    base_amount: Amount(1),
                    quote_amount: Amount(1),
                },
                auth: None,
            })
            .unwrap_err();
        assert_eq!(err, SettlementError::UnknownMarket(market()));
    }

    #[test]
    fn rejected_trade_rolls_back_fully() {
        let mut s = with_btc_usdc();
        s.apply(&deposit(buyer(), USDC, 500)).unwrap(); // not enough for a 1000 fill
        s.apply(&deposit(seller(), BTC, 5)).unwrap();
        let before = s.clone();

        let err = s
            .apply(&Tx::Trade {
                market: market(),
                fill: Fill {
                    buyer: buyer(),
                    seller: seller(),
                    base_amount: Amount(5),
                    quote_amount: Amount(1000),
                },
                auth: None,
            })
            .unwrap_err();
        assert_eq!(
            err,
            SettlementError::InsufficientBalance {
                account: buyer(),
                asset: USDC
            }
        );
        // The seller's BTC was debited mid-fill before the buyer's quote debit
        // failed; the transactional rollback must restore it. Whole-state equality
        // is the strongest possible check.
        assert_eq!(s, before);
    }

    // ---- Trade authorization (Phase 2: check_trade_auth) --------------------

    mod authz {
        use super::*;
        use crate::auth::{Ed25519PubKey, Ed25519Signature, Order, SignedOrder, TradeAuth};
        use ed25519_dalek::{Signer, SigningKey};

        fn keypair(seed: u8) -> (SigningKey, Ed25519PubKey) {
            let sk = SigningKey::from_bytes(&[seed; 32]);
            let pk = Ed25519PubKey(sk.verifying_key().to_bytes());
            (sk, pk)
        }
        fn sign(sk: &SigningKey, msg: &[u8]) -> Ed25519Signature {
            Ed25519Signature::from_bytes(sk.sign(msg).to_bytes())
        }

        /// A state with the market registered, both accounts funded + keyed, and
        /// an operator key set. Returns the state plus the three signing keys.
        fn setup() -> (State, SigningKey, SigningKey, SigningKey) {
            let (buyer_sk, buyer_pk) = keypair(1);
            let (seller_sk, seller_pk) = keypair(2);
            let (op_sk, op_pk) = keypair(3);

            let mut s = with_btc_usdc();
            s.set_operator_key(op_pk);
            s.apply(&Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(10_000),
                nonce: 100,
                owner: buyer_owner(),
                trading_key: Some(buyer_pk),
            })
            .unwrap();
            s.apply(&Tx::Deposit {
                account: seller(),
                asset: BTC,
                amount: Amount(100),
                nonce: 101,
                owner: seller_owner(),
                trading_key: Some(seller_pk),
            })
            .unwrap();
            (s, buyer_sk, seller_sk, op_sk)
        }

        fn buy_order(salt: u64) -> Order {
            Order {
                account: buyer(),
                market: market(),
                side: Side::Buy,
                base_amount: Amount(5),
                limit_price: Amount(250), // pays at most 250 quote per base
                expiry: 10,
                salt,
            }
        }
        fn sell_order(salt: u64) -> Order {
            Order {
                account: seller(),
                market: market(),
                side: Side::Sell,
                base_amount: Amount(5),
                limit_price: Amount(180), // wants at least 180 quote per base
                expiry: 10,
                salt,
            }
        }
        fn fill(base: i128, quote: i128) -> Fill {
            Fill {
                buyer: buyer(),
                seller: seller(),
                base_amount: Amount(base),
                quote_amount: Amount(quote),
            }
        }

        /// Assemble a `TradeAuth` with honestly-signed orders + matcher sig.
        fn authorize(
            buyer_sk: &SigningKey,
            seller_sk: &SigningKey,
            op_sk: &SigningKey,
            buy: Order,
            sell: Order,
            f: &Fill,
        ) -> TradeAuth {
            let buy_sig = sign(buyer_sk, &encode_order(&buy));
            let sell_sig = sign(seller_sk, &encode_order(&sell));
            let m = encode_matcher_msg(market(), &order_id(&buy), &order_id(&sell), f);
            TradeAuth {
                buy: SignedOrder {
                    order: buy,
                    sig: buy_sig,
                },
                sell: SignedOrder {
                    order: sell,
                    sig: sell_sig,
                },
                matcher_sig: sign(op_sk, &m),
            }
        }

        /// Apply a fully-signed trade through `State::apply`.
        fn apply_trade(
            s: &mut State,
            b: &SigningKey,
            se: &SigningKey,
            op: &SigningKey,
            f: Fill,
        ) -> Result<StateDelta, SettlementError> {
            let auth = authorize(b, se, op, buy_order(1), sell_order(2), &f);
            s.apply(&Tx::Trade {
                market: market(),
                fill: f,
                auth: Some(Box::new(auth)),
            })
        }

        #[test]
        fn valid_trade_authorizes_and_records_partial_fills() {
            let (mut s, b, se, op) = setup();
            let buy_id = order_id(&buy_order(1));

            apply_trade(&mut s, &b, &se, &op, fill(2, 400)).unwrap();
            assert_eq!(s.order_filled(buyer(), &buy_id), Amount(2));

            // A second partial fill (3 more) completes the size-5 orders.
            apply_trade(&mut s, &b, &se, &op, fill(3, 600)).unwrap();
            assert_eq!(s.order_filled(buyer(), &buy_id), Amount(5));
        }

        #[test]
        fn cumulative_over_fill_is_rejected() {
            let (mut s, b, se, op) = setup();
            apply_trade(&mut s, &b, &se, &op, fill(4, 800)).unwrap();

            // 4 already filled; another 2 would exceed the size-5 orders.
            assert_eq!(
                apply_trade(&mut s, &b, &se, &op, fill(2, 400)),
                Err(SettlementError::OrderOverfilled)
            );
        }

        #[test]
        fn single_over_fill_is_rejected() {
            let (s, b, se, op) = setup();
            let f = fill(10, 2000); // > order base_amount 5
            let auth = authorize(&b, &se, &op, buy_order(1), sell_order(2), &f);
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::OrderOverfilled)
            );
        }

        #[test]
        fn forged_user_signature_is_rejected() {
            let (s, _b, se, op) = setup();
            let (wrong, _) = keypair(9); // not the buyer's key
            let f = fill(2, 400);
            let auth = authorize(&wrong, &se, &op, buy_order(1), sell_order(2), &f);
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::InvalidOrderSignature)
            );
        }

        #[test]
        fn forged_matcher_signature_is_rejected() {
            let (s, b, se, _op) = setup();
            let (wrong_op, _) = keypair(9); // not the registered operator key
            let f = fill(2, 400);
            let auth = authorize(&b, &se, &wrong_op, buy_order(1), sell_order(2), &f);
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::InvalidMatcherSignature)
            );
        }

        #[test]
        fn missing_trading_key_is_rejected() {
            // Operator key set, but the buyer never registered a trading key.
            let (_b, buyer_pk) = keypair(1);
            let (seller_sk, seller_pk) = keypair(2);
            let (op_sk, op_pk) = keypair(3);
            let mut s = with_btc_usdc();
            s.set_operator_key(op_pk);
            // buyer funded WITHOUT a key:
            s.apply(&deposit(buyer(), USDC, 10_000)).unwrap();
            s.apply(&Tx::Deposit {
                account: seller(),
                asset: BTC,
                amount: Amount(100),
                nonce: 200,
                owner: seller_owner(),
                trading_key: Some(seller_pk),
            })
            .unwrap();
            let _ = buyer_pk;

            let f = fill(2, 400);
            let (buyer_sk_wrong, _) = keypair(1);
            let auth = authorize(
                &buyer_sk_wrong,
                &seller_sk,
                &op_sk,
                buy_order(1),
                sell_order(2),
                &f,
            );
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::MissingTradingKey { account: buyer() })
            );
        }

        #[test]
        fn expired_order_is_rejected() {
            let (mut s, b, se, op) = setup();
            s.set_batch_height(20); // orders expire at height 10
            let f = fill(2, 400);
            let auth = authorize(&b, &se, &op, buy_order(1), sell_order(2), &f);
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::OrderExpired)
            );
        }

        #[test]
        fn price_violation_is_rejected() {
            let (s, b, se, op) = setup();
            // implied price 300 > buyer's limit 250.
            let f = fill(2, 600);
            let auth = authorize(&b, &se, &op, buy_order(1), sell_order(2), &f);
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::PriceViolation)
            );
        }

        #[test]
        fn tampered_order_terms_break_the_signature() {
            let (s, b, se, op) = setup();
            let f = fill(2, 400);
            // Sign the honest order, then swap in a different order under the same
            // signature (raising the buyer's authorized size).
            let mut auth = authorize(&b, &se, &op, buy_order(1), sell_order(2), &f);
            auth.buy.order.base_amount = Amount(1000);
            assert_eq!(
                s.check_trade_auth(market(), &f, &auth),
                Err(SettlementError::InvalidOrderSignature)
            );
        }

        // ---- through `State::apply` (the wired Tx::Trade path) --------------

        #[test]
        fn apply_authenticated_trade_settles_and_records() {
            let (mut s, b, se, op) = setup();
            let f = fill(2, 400);
            let auth = authorize(&b, &se, &op, buy_order(1), sell_order(2), &f);
            s.apply(&Tx::Trade {
                market: market(),
                fill: f.clone(),
                auth: Some(Box::new(auth)),
            })
            .unwrap();

            // Balances swapped per the fill…
            assert_eq!(s.balance(buyer(), BTC), Amount(2));
            assert_eq!(s.balance(seller(), USDC), Amount(400));
            // …and the fill was recorded against the orders.
            assert_eq!(s.order_filled(buyer(), &order_id(&buy_order(1))), Amount(2));
        }

        #[test]
        fn apply_trade_without_auth_rejected_when_operator_key_set() {
            let (mut s, ..) = setup();
            let before = s.clone();
            let err = s
                .apply(&Tx::Trade {
                    market: market(),
                    fill: fill(2, 400),
                    auth: None,
                })
                .unwrap_err();
            assert_eq!(err, SettlementError::InvalidMatcherSignature);
            assert_eq!(s, before); // nothing moved
        }

        #[test]
        fn apply_forged_trade_rejected_and_rolls_back() {
            let (mut s, b, se, op) = setup();
            let before = s.clone();
            let f = fill(2, 400);
            let mut auth = authorize(&b, &se, &op, buy_order(1), sell_order(2), &f);
            auth.buy.order.base_amount = Amount(1000); // breaks the signature
            let err = s
                .apply(&Tx::Trade {
                    market: market(),
                    fill: f,
                    auth: Some(Box::new(auth)),
                })
                .unwrap_err();
            assert_eq!(err, SettlementError::InvalidOrderSignature);
            // Authorization fails before settlement — full rollback, incl. fills.
            assert_eq!(s, before);
        }
    }
}
