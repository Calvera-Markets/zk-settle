//! S6: solvency of `MockSettlementContract` over random settled sequences.
//!
//! After every `verify_next`, `claim`, and `escape_withdraw`:
//! `escrow(asset) == Σ L2 balances(asset) + pending_withdrawals(asset)`.
//! In-flight committed-but-unverified batches are not asserted.

use std::collections::BTreeSet;

use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::commitment::{withdrawal_proof, StateTree};
use clearing::da;
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, L1Address, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{Engine, ExecutingProver, MockSettlementContract, SettleError, Tx};
use proptest::prelude::*;
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
fn market() -> MarketId {
    MarketId(Uuid::from_u128(0xA1))
}
fn genesis() -> clearing::Hash {
    StateTree::new(Sha256Hasher).root()
}

fn who(buyer_side: bool) -> (AccountId, L1Address) {
    if buyer_side {
        (buyer(), buyer_owner())
    } else {
        (seller(), seller_owner())
    }
}
fn asset(usdc: bool) -> AssetId {
    if usdc {
        USDC
    } else {
        BTC
    }
}

#[derive(Clone, Debug)]
enum Action {
    Deposit {
        buyer_side: bool,
        usdc: bool,
        amount: i128,
    },
    Trade {
        base: i128,
        quote: i128,
    },
    Withdraw {
        buyer_side: bool,
        usdc: bool,
        amount: i128,
    },
    Claim,
    Freeze,
    Escape {
        buyer_side: bool,
        usdc: bool,
    },
}

#[derive(Clone, Copy)]
struct Claimable {
    batch_seq: u64,
    index: u32,
    owner: L1Address,
    asset: AssetId,
    amount: Amount,
}

struct Harness {
    engine: Engine<Sha256Hasher, ExecutingProver<Sha256Hasher>>,
    contract: MockSettlementContract<ExecutingProver<Sha256Hasher>>,
    next_seq: u64,
    batches: Vec<Vec<(L1Address, AssetId, Amount)>>,
    unclaimed: Vec<Claimable>,
    escaped: BTreeSet<(AccountId, AssetId)>,
}

impl Harness {
    fn new() -> Self {
        let mut engine = Engine::new(Sha256Hasher, ExecutingProver::new(Sha256Hasher));
        engine.register_market(
            market(),
            Instrument {
                id: InstrumentId(1),
                kind: SettlementKind::SpotSwap,
                base: BTC,
                quote: USDC,
                base_scale: 8,
                quote_scale: 6,
            },
        );
        let contract = MockSettlementContract::new(ExecutingProver::new(Sha256Hasher), genesis());
        Self {
            engine,
            contract,
            next_seq: 0,
            batches: Vec::new(),
            unclaimed: Vec::new(),
            escaped: BTreeSet::new(),
        }
    }

    fn assets() -> [AssetId; 2] {
        [USDC, BTC]
    }

    fn assert_settled(&self) {
        assert!(self
            .contract
            .is_solvent(self.engine.state(), &Self::assets()));
        assert_eq!(self.contract.root(), self.engine.root());
    }

    fn apply_and_verify(&mut self, txs: Vec<Tx>) {
        let outcome = self.engine.step(txs).unwrap();
        self.contract.commit(outcome.proposal()).unwrap();
        let root = self.contract.verify_next(&Sha256Hasher).unwrap();
        assert_eq!(root, outcome.new_root());
        let seq = self.next_seq;
        self.next_seq += 1;
        let entries: Vec<(L1Address, AssetId, Amount)> = outcome
            .messages
            .iter()
            .map(
                |clearing::OnChainMessage::Withdraw {
                     owner,
                     asset,
                     amount,
                 }| { (*owner, *asset, *amount) },
            )
            .collect();
        for (i, (owner, asset, amount)) in entries.iter().enumerate() {
            self.unclaimed.push(Claimable {
                batch_seq: seq,
                index: i as u32,
                owner: *owner,
                asset: *asset,
                amount: *amount,
            });
        }
        self.batches.push(entries);
        self.assert_settled();
    }

    fn run(&mut self, actions: &[Action]) {
        for action in actions {
            if self.contract.is_frozen() {
                match action {
                    Action::Escape { buyer_side, usdc } => self.escape(*buyer_side, *usdc),
                    _ => {
                        assert_eq!(
                            self.contract.verify_next(&Sha256Hasher),
                            Err(SettleError::Frozen)
                        );
                    }
                }
                continue;
            }
            match action {
                Action::Deposit {
                    buyer_side,
                    usdc,
                    amount,
                } => {
                    let (account, owner) = who(*buyer_side);
                    let d = self
                        .contract
                        .deposit(account, asset(*usdc), Amount(*amount), owner)
                        .unwrap();
                    self.apply_and_verify(vec![d]);
                }
                Action::Trade { base, quote } => {
                    let buyer_usdc = self.engine.state().balance(buyer(), USDC);
                    let seller_btc = self.engine.state().balance(seller(), BTC);
                    let base = Amount(*base).min(seller_btc);
                    let quote = Amount(*quote).min(buyer_usdc);
                    if base.is_zero() || quote.is_zero() {
                        continue;
                    }
                    self.apply_and_verify(vec![Tx::Trade {
                        market: market(),
                        fill: Fill {
                            buyer: buyer(),
                            seller: seller(),
                            base_amount: base,
                            quote_amount: quote,
                        },
                        auth: None,
                    }]);
                }
                Action::Withdraw {
                    buyer_side,
                    usdc,
                    amount,
                } => {
                    let (account, _) = who(*buyer_side);
                    let have = self.engine.state().balance(account, asset(*usdc));
                    let amt = Amount(*amount).min(have);
                    if amt.is_zero() {
                        continue;
                    }
                    self.apply_and_verify(vec![Tx::Withdraw {
                        account,
                        asset: asset(*usdc),
                        amount: amt,
                    }]);
                }
                Action::Claim => self.claim_one(),
                Action::Freeze => {
                    self.contract.freeze();
                    assert!(self.contract.is_frozen());
                    assert_eq!(
                        self.contract.verify_next(&Sha256Hasher),
                        Err(SettleError::Frozen)
                    );
                    self.assert_settled();
                }
                Action::Escape { buyer_side, usdc } => self.escape(*buyer_side, *usdc),
            }
        }
    }

    fn claim_one(&mut self) {
        let Some(c) = self.unclaimed.first().copied() else {
            return;
        };
        let entries = &self.batches[c.batch_seq as usize];
        let siblings = withdrawal_proof(&Sha256Hasher, c.batch_seq, entries, c.index as usize);
        let escrow_before = self.contract.total_escrow(c.asset);
        let pending_before = self.contract.pending_withdrawals(c.asset);
        self.contract
            .claim(
                &Sha256Hasher,
                c.batch_seq as usize,
                c.index,
                c.owner,
                c.asset,
                c.amount,
                &siblings,
            )
            .unwrap();
        assert_eq!(
            self.contract.total_escrow(c.asset),
            escrow_before - c.amount.0
        );
        assert_eq!(
            self.contract.pending_withdrawals(c.asset),
            pending_before.checked_sub(c.amount).unwrap()
        );
        self.assert_settled();
        let replay = self.contract.claim(
            &Sha256Hasher,
            c.batch_seq as usize,
            c.index,
            c.owner,
            c.asset,
            c.amount,
            &siblings,
        );
        assert_eq!(replay, Err(SettleError::AlreadyClaimed));
        assert_eq!(
            self.contract.total_escrow(c.asset),
            escrow_before - c.amount.0
        );
        self.assert_settled();
        self.unclaimed.remove(0);
    }

    fn escape(&mut self, buyer_side: bool, usdc: bool) {
        if !self.contract.is_frozen() {
            return;
        }
        let (account, owner) = who(buyer_side);
        let a = asset(usdc);
        if self.escaped.contains(&(account, a)) {
            let accounts = da::reconstruct(self.contract.da_blobs());
            let Some(proven) = accounts.get(&account).cloned() else {
                return;
            };
            let tree = StateTree::from_accounts(Sha256Hasher, accounts.iter());
            let (mask, sibs) = tree.prove(account);
            assert_eq!(
                self.contract.escape_withdraw(
                    &Sha256Hasher,
                    account,
                    &proven,
                    mask,
                    &sibs,
                    a,
                    owner,
                ),
                Err(SettleError::AlreadyEscaped)
            );
            return;
        }
        let accounts = da::reconstruct(self.contract.da_blobs());
        let tree = StateTree::from_accounts(Sha256Hasher, accounts.iter());
        assert_eq!(tree.root(), self.contract.root());
        let Some(proven) = accounts.get(&account).cloned() else {
            return;
        };
        let (mask, sibs) = tree.prove(account);
        if proven.balance(a).is_zero() {
            return;
        }
        // Theft: other owner, same leaf. Merkle ok, owner check fails.
        let other = if buyer_side {
            seller_owner()
        } else {
            buyer_owner()
        };
        let escrow_before = self.contract.total_escrow(a);
        assert_eq!(
            self.contract
                .escape_withdraw(&Sha256Hasher, account, &proven, mask, &sibs, a, other,),
            Err(SettleError::OwnerMismatch)
        );
        assert_eq!(self.contract.total_escrow(a), escrow_before);

        let got = self
            .contract
            .escape_withdraw(&Sha256Hasher, account, &proven, mask, &sibs, a, owner)
            .unwrap();
        assert_eq!(got, proven.balance(a));
        self.escaped.insert((account, a));
        self.assert_settled();
    }
}

fn action_strategy() -> impl Strategy<Value = Action> {
    prop_oneof![
        (any::<bool>(), any::<bool>(), 1i128..500).prop_map(|(b, u, a)| Action::Deposit {
            buyer_side: b,
            usdc: u,
            amount: a,
        }),
        (1i128..200, 1i128..200).prop_map(|(base, quote)| Action::Trade { base, quote }),
        (any::<bool>(), any::<bool>(), 1i128..200).prop_map(|(b, u, a)| Action::Withdraw {
            buyer_side: b,
            usdc: u,
            amount: a,
        }),
        Just(Action::Claim),
        Just(Action::Freeze),
        (any::<bool>(), any::<bool>()).prop_map(|(b, u)| Action::Escape {
            buyer_side: b,
            usdc: u,
        }),
    ]
}

/// One scripted sequence used as a compile/smoke check for the generator.
#[test]
fn strategy_plays_deposit_trade_withdraw_claim() {
    let mut h = Harness::new();
    h.run(&[
        Action::Deposit {
            buyer_side: true,
            usdc: true,
            amount: 1000,
        },
        Action::Deposit {
            buyer_side: false,
            usdc: false,
            amount: 5,
        },
        Action::Trade {
            base: 2,
            quote: 400,
        },
        Action::Withdraw {
            buyer_side: true,
            usdc: true,
            amount: 100,
        },
        Action::Claim,
    ]);
    assert_eq!(h.contract.pending_withdrawals(USDC), Amount::ZERO);
    h.assert_settled();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn solvency_holds_over_random_sequences(actions in proptest::collection::vec(action_strategy(), 1..12)) {
        let mut h = Harness::new();
        h.run(&actions);
        h.assert_settled();
    }
}
