//! The canonical top-to-bottom read: a full deposit → trade → withdraw loop with
//! the mock settlement contract finalizing every batch, and solvency asserted at
//! each settled point.
//!
//! This is the whole protocol in one test:
//!
//! 1. **Deposit** — funds escrow on the contract (L1 custody) and credit the L2
//!    state; the batch commits and its proof verifies, advancing the canonical
//!    root.
//! 2. **Trade** — an internal redistribution between accounts (per-asset totals
//!    unchanged); committed and verified.
//! 3. **Withdraw** — the L2 balance is debited and, on the batch verifying, the
//!    contract releases escrow to the owner's L1 address.
//!
//! Throughout, the engine's `new_root` chain and the contract's canonical root
//! stay in lockstep, and **solvency** (per asset: escrow == Σ L2 balances) holds
//! at every settled point.
//!
//! NOTE: deposits/withdrawals are mirrored on both sides *by hand* here (escrow
//! on the contract, balance on L2) because the automatic binding is S2/S3 of
//! `../docs/settlement-l1-plan.md`. When those land this test simplifies to "the
//! batch carries the deposit/withdrawal and the contract applies it on verify".

use clearing::auth::{Ed25519PubKey, Ed25519Signature, Order, Side, SignedOrder, TradeAuth};
use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::commitment::{encode_matcher_msg, encode_order, order_id, withdrawal_proof};
use clearing::id::{AccountId, Amount, AssetId, InstrumentId, L1Address, MarketId};
use clearing::instrument::{Instrument, SettlementKind};
use clearing::settlement::Fill;
use clearing::{
    Engine, ExecutingProver, MockSettlementContract, ReplayProver, SettleError, StateTree, Tx,
};
use ed25519_dalek::{Signer, SigningKey};
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

fn engine() -> Engine<Sha256Hasher, ReplayProver<Sha256Hasher>> {
    let mut e = Engine::new(Sha256Hasher, ReplayProver::new(Sha256Hasher));
    e.register_market(
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
    e
}

#[test]
fn deposit_trade_withdraw_settles_and_stays_solvent() {
    let assets = [USDC, BTC];
    let mut engine = engine();
    let mut contract = MockSettlementContract::new(ExecutingProver::new(Sha256Hasher), genesis());

    assert_eq!(contract.root(), genesis());
    let mut roots = vec![contract.root()];

    // ---- Batch 1: deposits ------------------------------------------------
    // The contract escrows and issues each deposit tx; the engine includes them;
    // verifying the batch finalizes the L2 credit.
    let d_buyer = contract
        .deposit(buyer(), USDC, Amount(1000), buyer_owner())
        .unwrap();
    let d_seller = contract
        .deposit(seller(), BTC, Amount(5), seller_owner())
        .unwrap();
    let o1 = engine.step(vec![d_buyer, d_seller]).unwrap();
    assert_eq!(o1.prev_root(), genesis());

    contract.commit(o1.proposal()).unwrap();
    assert_eq!(contract.verify_next(&Sha256Hasher).unwrap(), o1.new_root());
    assert_eq!(contract.root(), engine.root());
    assert!(contract.is_solvent(engine.state(), &assets));
    roots.push(contract.root());

    // ---- Batch 2: trade (internal redistribution; totals unchanged) -------
    let o2 = engine
        .step(vec![Tx::Trade {
            market: market(),
            fill: Fill {
                buyer: buyer(),
                seller: seller(),
                base_amount: Amount(2),
                quote_amount: Amount(400),
            },
            auth: None,
        }])
        .unwrap();
    assert_eq!(o2.prev_root(), contract.root()); // chains onto the last verified root

    contract.commit(o2.proposal()).unwrap();
    assert_eq!(contract.verify_next(&Sha256Hasher).unwrap(), o2.new_root());
    assert!(contract.is_solvent(engine.state(), &assets)); // a trade conserves per-asset totals
    roots.push(contract.root());

    // balances moved between accounts, custody totals did not
    assert_eq!(engine.state().balance(buyer(), BTC), Amount(2));
    assert_eq!(engine.state().balance(seller(), USDC), Amount(400));
    assert_eq!(contract.total_escrow(USDC), 1000);

    // ---- Batch 3: withdrawal (debit L2; commit a withdrawals root) --------
    let o3 = engine
        .step(vec![Tx::Withdraw {
            account: buyer(),
            asset: USDC,
            amount: Amount(100),
        }])
        .unwrap();
    // The withdrawal emits exactly one on-chain message; destination is the
    // L1 owner bound at deposit (the Solana pubkey, not the account id).
    assert_eq!(o3.messages.len(), 1);

    contract.commit(o3.proposal()).unwrap();
    // Verifying commits the batch's withdrawals as ONE root — it does NOT pay out.
    // Escrow still holds the 100 USDC, now tracked as an authorized-but-unclaimed
    // pending withdrawal; solvency accounts for it (escrow == Σ L2 + pending).
    assert_eq!(contract.verify_next(&Sha256Hasher).unwrap(), o3.new_root());
    assert_eq!(contract.total_escrow(USDC), 1000); // not released yet
    assert_eq!(contract.pending_withdrawals(USDC), Amount(100));
    assert!(contract.is_solvent(engine.state(), &assets));
    roots.push(contract.root());

    // The buyer PULLS the payout asynchronously: prove inclusion in batch 2's
    // (the 3rd finalized batch) withdrawals root, get paid, nullify.
    let owner = buyer_owner();
    let entries = [(owner, USDC, Amount(100))];
    let siblings = withdrawal_proof(&Sha256Hasher, 2, &entries, 0);
    contract
        .claim(&Sha256Hasher, 2, 0, owner, USDC, Amount(100), &siblings)
        .unwrap();
    assert_eq!(contract.total_escrow(USDC), 900); // now released
    assert_eq!(contract.pending_withdrawals(USDC), Amount::ZERO);
    assert!(contract.is_solvent(engine.state(), &assets));
    // A second claim (replay) is rejected by the nullifier.
    assert!(
        contract
            .claim(&Sha256Hasher, 2, 0, owner, USDC, Amount(100), &siblings)
            .is_err()
    );

    // ---- whole-loop assertions --------------------------------------------
    // Every batch advanced the root, and the chain is unbroken from genesis to
    // the contract's canonical root, which equals the engine's.
    for pair in roots.windows(2) {
        assert_ne!(pair[0], pair[1]);
    }
    assert_eq!(*roots.last().unwrap(), engine.root());
    assert_eq!(contract.root(), engine.root());

    // Exact final L2 balances.
    let s = engine.state();
    assert_eq!(s.balance(buyer(), USDC), Amount(500));
    assert_eq!(s.balance(buyer(), BTC), Amount(2));
    assert_eq!(s.balance(seller(), USDC), Amount(400));
    assert_eq!(s.balance(seller(), BTC), Amount(3));

    // 100 USDC actually left custody; BTC custody untouched. Still solvent:
    // total escrow == total L2 (900 USDC, 5 BTC), even though per-owner escrow
    // and per-account L2 differ (claims move via trading; custody is aggregate).
    assert_eq!(contract.total_escrow(USDC), 900);
    assert_eq!(contract.total_escrow(BTC), 5);
}

/// The spoof you can't express: a withdrawal is only ever a *proven L2 debit*.
///
/// After funding and a trade, the buyer holds 600 USDC at L2 but custody still
/// escrows 1000 (the trade was internal). An attacker tries to drain 1000 by
/// withdrawing it — but the state machine rejects an over-balance withdrawal, so
/// the batch emits **no** message, the proven transition is a no-op, and the
/// contract releases nothing. There is no `release` to call directly, so the
/// only lever is a withdrawal `Tx`, which is bounded by the L2 balance.
#[test]
fn fail_spoof_withdraw() {
    let assets = [USDC, BTC];
    let mut engine = engine();
    let mut contract = MockSettlementContract::new(ExecutingProver::new(Sha256Hasher), genesis());

    // Fund + trade so the buyer's L2 USDC (600) is below their escrowed 1000.
    let d_buyer = contract
        .deposit(buyer(), USDC, Amount(1000), buyer_owner())
        .unwrap();
    let d_seller = contract
        .deposit(seller(), BTC, Amount(5), seller_owner())
        .unwrap();
    let o1 = engine.step(vec![d_buyer, d_seller]).unwrap();
    contract.commit(o1.proposal()).unwrap();
    contract.verify_next(&Sha256Hasher).unwrap();

    let o2 = engine
        .step(vec![Tx::Trade {
            market: market(),
            fill: Fill {
                buyer: buyer(),
                seller: seller(),
                base_amount: Amount(2),
                quote_amount: Amount(400),
            },
            auth: None,
        }])
        .unwrap();
    contract.commit(o2.proposal()).unwrap();
    contract.verify_next(&Sha256Hasher).unwrap();

    assert_eq!(engine.state().balance(buyer(), USDC), Amount(600));
    assert_eq!(contract.total_escrow(USDC), 1000);
    assert!(contract.is_solvent(engine.state(), &assets));

    // The spoof: withdraw 1000 USDC the buyer doesn't have at L2.
    let spoof = engine
        .step(vec![Tx::Withdraw {
            account: buyer(),
            asset: USDC,
            amount: Amount(1000),
        }])
        .unwrap();
    // Rejected by the state machine ⇒ no debit, no message, no-op transition.
    assert!(spoof.messages.is_empty());
    assert_eq!(spoof.prev_root(), spoof.new_root());

    contract.commit(spoof.proposal()).unwrap();
    contract.verify_next(&Sha256Hasher).unwrap();

    // Nothing was released; the contract is still solvent and balances intact.
    assert_eq!(contract.total_escrow(USDC), 1000);
    assert_eq!(engine.state().balance(buyer(), USDC), Amount(600));
    assert!(contract.is_solvent(engine.state(), &assets));
}

// ---- Authenticated trades through the contract --------------------------------

fn kp(seed: u8) -> (SigningKey, Ed25519PubKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = Ed25519PubKey(sk.verifying_key().to_bytes());
    (sk, pk)
}
fn sig(sk: &SigningKey, m: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(sk.sign(m).to_bytes())
}

/// An engine + contract both configured with the operator key, plus the buyer,
/// seller, and operator signing keys.
type AuthedSetup = (
    Engine<Sha256Hasher, ExecutingProver<Sha256Hasher>>,
    MockSettlementContract<ExecutingProver<Sha256Hasher>>,
    SigningKey,
    SigningKey,
    SigningKey,
);

/// An engine + contract both configured with the operator key, so trades are
/// authorized at capture *and* re-verified at the contract. Plus the three keys.
fn authed_engine() -> AuthedSetup {
    let (buyer_sk, _) = kp(1);
    let (seller_sk, _) = kp(2);
    let (op_sk, op_pk) = kp(3);

    // Both the engine's prover and the contract's verifier carry the operator key
    // (verifier config, not witness data), so both enforce authorization.
    let mut e = Engine::new(
        Sha256Hasher,
        ExecutingProver::with_auth(Sha256Hasher, op_pk, 0),
    );
    e.register_market(
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
    e.set_operator_key(op_pk);
    let c = MockSettlementContract::new(
        ExecutingProver::with_auth(Sha256Hasher, op_pk, 0),
        genesis(),
    );
    (e, c, buyer_sk, seller_sk, op_sk)
}

fn buy_order() -> Order {
    Order {
        account: buyer(),
        market: market(),
        side: Side::Buy,
        base_amount: Amount(5),
        limit_price: Amount(250),
        expiry: 1000,
        salt: 1,
    }
}
fn sell_order() -> Order {
    Order {
        account: seller(),
        market: market(),
        side: Side::Sell,
        base_amount: Amount(5),
        limit_price: Amount(180),
        expiry: 1000,
        salt: 2,
    }
}

/// A fully-signed trade tx for a `base`/`quote` fill.
fn signed_trade(
    buyer_sk: &SigningKey,
    seller_sk: &SigningKey,
    op_sk: &SigningKey,
    base: i128,
    quote: i128,
) -> Tx {
    let f = Fill {
        buyer: buyer(),
        seller: seller(),
        base_amount: Amount(base),
        quote_amount: Amount(quote),
    };
    let (buy, sell) = (buy_order(), sell_order());
    let m = encode_matcher_msg(market(), &order_id(&buy), &order_id(&sell), &f);
    let auth = TradeAuth {
        buy: SignedOrder {
            order: buy,
            sig: sig(buyer_sk, &encode_order(&buy)),
        },
        sell: SignedOrder {
            order: sell,
            sig: sig(seller_sk, &encode_order(&sell)),
        },
        matcher_sig: sig(op_sk, &m),
    };
    Tx::Trade {
        market: market(),
        fill: f,
        auth: Some(Box::new(auth)),
    }
}

#[test]
fn authenticated_trade_settles_through_the_contract() {
    let (mut engine, mut contract, b, se, op) = authed_engine();

    // Batch 1: fund + register both trading keys (folded into the first deposit).
    let o1 = engine
        .step(vec![
            Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: buyer_owner(),
                trading_key: Some(kp(1).1),
            },
            Tx::Deposit {
                account: seller(),
                asset: BTC,
                amount: Amount(5),
                nonce: 1,
                owner: seller_owner(),
                trading_key: Some(kp(2).1),
            },
        ])
        .unwrap();
    contract.commit(o1.proposal()).unwrap();
    assert_eq!(contract.verify_next(&Sha256Hasher).unwrap(), o1.new_root());

    // Batch 2: a fully-signed trade. Authorized at capture, re-verified by the
    // contract's auth verifier.
    let o2 = engine
        .step(vec![signed_trade(&b, &se, &op, 2, 400)])
        .unwrap();
    contract.commit(o2.proposal()).unwrap();
    assert_eq!(contract.verify_next(&Sha256Hasher).unwrap(), o2.new_root());
    assert_eq!(engine.state().balance(buyer(), BTC), Amount(2));
    assert_eq!(engine.state().balance(seller(), USDC), Amount(400));
}

/// The attack `with_auth` on the contract exists to stop: a malicious operator
/// submits a batch whose committed transition includes a trade with a **forged**
/// matcher signature. The contract's auth verifier re-executes, the trade fails
/// authorization, and the re-executed leaves diverge from the claimed root — so
/// `verify_next` rejects the batch and the root does not advance.
#[test]
fn contract_rejects_forged_trade() {
    let (mut engine, mut contract, b, se, op) = authed_engine();

    let o1 = engine
        .step(vec![
            Tx::Deposit {
                account: buyer(),
                asset: USDC,
                amount: Amount(1000),
                nonce: 0,
                owner: buyer_owner(),
                trading_key: Some(kp(1).1),
            },
            Tx::Deposit {
                account: seller(),
                asset: BTC,
                amount: Amount(5),
                nonce: 1,
                owner: seller_owner(),
                trading_key: Some(kp(2).1),
            },
        ])
        .unwrap();
    contract.commit(o1.proposal()).unwrap();
    contract.verify_next(&Sha256Hasher).unwrap();

    // Produce a valid trade proposal, then tamper the matcher signature — the
    // roots still reflect the (authorized) trade.
    let o2 = engine
        .step(vec![signed_trade(&b, &se, &op, 2, 400)])
        .unwrap();
    let mut proposal = o2.proposal();
    for tx in proposal.witness.txs.iter_mut() {
        if let Tx::Trade {
            auth: Some(auth), ..
        } = tx
        {
            auth.matcher_sig.r[0] ^= 0xFF;
        }
    }

    let root_before = contract.root();
    contract.commit(proposal).unwrap(); // commit only checks the (untampered) prev_root
    assert!(contract.verify_next(&Sha256Hasher).is_err()); // proof re-verification rejects it
    assert_eq!(contract.root(), root_before); // root did not advance
}

/// DA-reconstructed leaf for account B, caller A, valid sparse path: escape
/// must reject `OwnerMismatch` and leave escrow untouched.
#[test]
fn escape_rejects_theft_of_another_accounts_leaf() {
    let mut engine = engine();
    let mut contract = MockSettlementContract::new(ExecutingProver::new(Sha256Hasher), genesis());

    let d_buyer = contract
        .deposit(buyer(), USDC, Amount(1000), buyer_owner())
        .unwrap();
    let d_seller = contract
        .deposit(seller(), BTC, Amount(5), seller_owner())
        .unwrap();
    let o1 = engine.step(vec![d_buyer, d_seller]).unwrap();
    contract.commit(o1.proposal()).unwrap();
    contract.verify_next(&Sha256Hasher).unwrap();

    let o2 = engine
        .step(vec![Tx::Trade {
            market: market(),
            fill: Fill {
                buyer: buyer(),
                seller: seller(),
                base_amount: Amount(2),
                quote_amount: Amount(400),
            },
            auth: None,
        }])
        .unwrap();
    contract.commit(o2.proposal()).unwrap();
    contract.verify_next(&Sha256Hasher).unwrap();

    contract.freeze();
    let accounts = clearing::da::reconstruct(contract.da_blobs());
    let tree = StateTree::from_accounts(Sha256Hasher, accounts.iter());
    let seller_acct = accounts.get(&seller()).cloned().unwrap();
    let (mask, sibs) = tree.prove(seller());

    let escrow_before = contract.total_escrow(USDC);
    assert_eq!(
        contract.escape_withdraw(
            &Sha256Hasher,
            seller(),
            &seller_acct,
            mask,
            &sibs,
            USDC,
            buyer_owner(),
        ),
        Err(SettleError::OwnerMismatch)
    );
    assert_eq!(contract.total_escrow(USDC), escrow_before);
}
